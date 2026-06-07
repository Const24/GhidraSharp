package io.github.const24.ghidrasharp.server.engine;

import ghidra.GhidraApplicationLayout;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.base.project.GhidraProject;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * {@link GhidraEngine} backed by Ghidra running as a library (headless).
 *
 * <p>Ghidra is initialized lazily on first use, then a single "current program"
 * is held across calls. Access is serialized: Ghidra's {@link DecompInterface}
 * and program access are not safe for concurrent use, and the vertical slice is
 * request-at-a-time. Batching/parallelism is a later concern.
 */
public final class GhidraLibraryEngine implements GhidraEngine {

    private static final int DEFAULT_TIMEOUT_SECONDS = 60;
    private static final String PROGRAM_CONTENT_TYPE = "Program";

    private final Object lock = new Object();
    private final String installDir;

    private boolean initialized;
    private GhidraProject project;
    private Program program;
    private DecompInterface decomp;

    public GhidraLibraryEngine() {
        String env = System.getenv("GHIDRA_INSTALL_DIR");
        this.installDir = (env != null && !env.isBlank()) ? env : "C:/ghidra_12.1_PUBLIC";
    }

    @Override
    public String name() {
        return "ghidra-library";
    }

    @Override
    public String ghidraVersion() {
        ensureInitialized();
        return Application.getApplicationVersion();
    }

    private void ensureInitialized() {
        synchronized (lock) {
            if (initialized) {
                return;
            }
            try {
                if (!Application.isInitialized()) {
                    GhidraApplicationLayout layout = new GhidraApplicationLayout(new File(installDir));
                    Application.initializeApplication(layout, new HeadlessGhidraApplicationConfiguration());
                }
                initialized = true;
            } catch (Exception e) {
                throw new IllegalStateException("Ghidra initialization failed (install=" + installDir + "): " + describe(e), e);
            }
        }
    }

    @Override
    public OpenResult open(String projectPath, String programPath, String languageId, boolean analyze) {
        try {
            ensureInitialized();
            synchronized (lock) {
                closeCurrent();

                if (projectPath != null && !projectPath.isBlank()) {
                    openFromProject(projectPath, programPath);
                } else if (programPath != null && new File(programPath).isFile()) {
                    importBinary(new File(programPath), analyze);
                } else {
                    return OpenResult.failure(
                            "program_path is neither a file on disk nor accompanied by an existing project_path: " + programPath);
                }

                bindDecompiler(program);
                return new OpenResult(
                        true,
                        program.getName(),
                        program.getLanguageID().getIdAsString(),
                        program.getImageBase().getOffset(),
                        program.getFunctionManager().getFunctionCount(),
                        "");
            }
        } catch (Exception e) {
            return OpenResult.failure(describe(e));
        }
    }

    @Override
    public DecompileResult decompile(String address, String name, int timeoutSeconds) {
        try {
            synchronized (lock) {
                if (program == null || decomp == null) {
                    return DecompileResult.failure("no program open; call OpenProgram first");
                }

                Function fn = resolveFunction(address, name);
                if (fn == null) {
                    String which = (address != null && !address.isBlank()) ? "address " + address : "name " + name;
                    return DecompileResult.failure("no function found at " + which);
                }

                int timeout = timeoutSeconds > 0 ? timeoutSeconds : DEFAULT_TIMEOUT_SECONDS;
                DecompileResults results = decomp.decompileFunction(fn, timeout, TaskMonitor.DUMMY);
                if (results == null || !results.decompileCompleted()) {
                    String err = (results != null && results.getErrorMessage() != null)
                            ? results.getErrorMessage()
                            : "decompiler returned no result";
                    return DecompileResult.failure(err.isBlank() ? "decompilation did not complete" : err);
                }

                return new DecompileResult(
                        true,
                        results.getDecompiledFunction().getC(),
                        results.getDecompiledFunction().getSignature(),
                        fn.getEntryPoint().toString(),
                        "");
            }
        } catch (Exception e) {
            return DecompileResult.failure(describe(e));
        }
    }

    // --- open helpers -------------------------------------------------------

    private void openFromProject(String projectPath, String desiredProgram) throws Exception {
        Path path = Path.of(projectPath);
        String projectDir;
        String projectName;

        String fileName = path.getFileName().toString();
        if (fileName.endsWith(".gpr") || fileName.endsWith(".rep")) {
            projectName = fileName.substring(0, fileName.length() - 4);
            projectDir = path.getParent().toString();
        } else if (Files.isDirectory(path)) {
            File gpr = findProjectFile(path.toFile());
            if (gpr == null) {
                throw new IllegalArgumentException("no .gpr project found under " + projectPath);
            }
            projectName = gpr.getName().substring(0, gpr.getName().length() - 4);
            projectDir = gpr.getParent();
        } else {
            throw new IllegalArgumentException("project_path is not a .gpr/.rep or a directory: " + projectPath);
        }

        project = GhidraProject.openProject(projectDir, projectName, false);
        program = openProgramFromProject(project, desiredProgram);
    }

    private static File findProjectFile(File dir) {
        File[] matches = dir.listFiles((d, n) -> n.endsWith(".gpr"));
        return (matches != null && matches.length > 0) ? matches[0] : null;
    }

    private Program openProgramFromProject(GhidraProject project, String desiredProgram) throws Exception {
        DomainFolder root = project.getRootFolder();
        DomainFile chosen = null;
        for (DomainFile df : root.getFiles()) {
            if (!PROGRAM_CONTENT_TYPE.equals(df.getContentType())) {
                continue;
            }
            if (desiredProgram != null && !desiredProgram.isBlank() && df.getName().equals(desiredProgram)) {
                chosen = df;
                break;
            }
            if (chosen == null) {
                chosen = df; // first program as fallback
            }
        }
        if (chosen == null) {
            throw new IllegalStateException("no Program found in project root folder");
        }
        return project.openProgram(root.getPathname(), chosen.getName(), true /* read-only */);
    }

    private void importBinary(File file, boolean analyze) throws Exception {
        project = GhidraProject.createProject(
                System.getProperty("java.io.tmpdir"),
                "ghidrasharp_scratch_" + System.nanoTime(),
                true /* temporary */);
        program = project.importProgram(file); // language auto-detected
        if (analyze) {
            GhidraProject.analyze(program);
        }
    }

    // --- decompile helpers --------------------------------------------------

    private Function resolveFunction(String address, String name) {
        if (address != null && !address.isBlank()) {
            Address entry = parseAddress(address);
            return entry == null ? null : program.getFunctionManager().getFunctionAt(entry);
        }
        if (name != null && !name.isBlank()) {
            for (Function fn : program.getFunctionManager().getFunctions(true)) {
                if (fn.getName().equals(name)) {
                    return fn;
                }
            }
        }
        return null;
    }

    private Address parseAddress(String address) {
        String s = address.trim().toLowerCase();
        if (s.startsWith("0x")) {
            s = s.substring(2);
        }
        try {
            long offset = Long.parseLong(s, 16);
            return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private void bindDecompiler(Program program) {
        decomp = new DecompInterface();
        if (!decomp.openProgram(program)) {
            String msg = decomp.getLastMessage();
            decomp.dispose();
            decomp = null;
            throw new IllegalStateException("decompiler failed to open program: " + msg);
        }
    }

    private void closeCurrent() {
        if (decomp != null) {
            decomp.dispose();
            decomp = null;
        }
        if (project != null) {
            project.close();
            project = null;
        }
        program = null;
    }

    private static String describe(Throwable t) {
        StringBuilder sb = new StringBuilder(t.getClass().getSimpleName());
        if (t.getMessage() != null) {
            sb.append(": ").append(t.getMessage());
        }
        Throwable cause = t.getCause();
        if (cause != null && cause != t) {
            sb.append(" <- ").append(cause.getClass().getSimpleName());
            if (cause.getMessage() != null) {
                sb.append(": ").append(cause.getMessage());
            }
        }
        return sb.toString();
    }
}
