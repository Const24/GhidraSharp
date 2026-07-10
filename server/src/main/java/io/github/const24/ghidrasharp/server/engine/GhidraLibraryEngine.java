package io.github.const24.ghidrasharp.server.engine;

import ghidra.GhidraApplicationLayout;
import generic.jar.ResourceFile;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptProvider;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.script.GhidraState;
import ghidra.app.script.ScriptControls;
import ghidra.app.util.importer.ProgramLoader;
import ghidra.app.util.opinion.LoadResults;
import ghidra.base.project.GhidraProject;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.lang.LanguageDescription;
import ghidra.program.model.lang.LanguageService;
import ghidra.program.model.lang.OperandType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.util.DefinedDataIterator;
import ghidra.program.model.listing.Data;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.task.TaskMonitor;

import java.io.File;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.Iterator;
import java.util.List;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

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
    private static final int MAX_READ_BYTES = 1 << 20;       // 1 MiB cap per ReadBytes
    private static final int DEFAULT_INSTRUCTIONS = 64;       // when no count and not inside a function
    // Recycle the native decompiler process every N functions during a whole-program decompile. A single
    // DecompInterface owns one decompile.exe whose resident memory only GROWS across a run (it does not shrink
    // mid-batch); on a giant binary (e.g. ~90k functions) that creeps to multiple GB per server and breaks any
    // pool that runs several servers on a RAM-bounded host. Disposing + rebinding resets the process. See setOptions.
    private static final int DECOMP_RECYCLE_EVERY = 1500;
    private static final int DECOMP_MAX_PAYLOAD_MB = 50;      // cap a single function's decompile payload (Ghidra default)
    // Cap instructions the decompiler processes per function, BELOW Ghidra's 100k default. A single pathological
    // function (huge/obfuscated body) can make the NATIVE decompile.exe commit tens of GB — that peak lives outside
    // the JVM heap, so -Xmx does not bound it, and recycling only resets RSS BETWEEN functions, not within one. This
    // is the one lever that bounds a single function's peak: the decompiler bails early past the cap. 50k spares all
    // legit functions (<~10-20k instructions); a bailed monster (garbage decompile anyway) returns a failure result.
    private static final int DECOMP_MAX_INSTRUCTIONS = 50_000;

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
    public OpenResult open(String projectPath, String programPath, String languageId, boolean analyze, boolean writable) {
        try {
            ensureInitialized();
            synchronized (lock) {
                closeCurrent();

                if (projectPath != null && !projectPath.isBlank()) {
                    openFromProject(projectPath, programPath, writable);
                } else if (programPath != null && new File(programPath).isFile()) {
                    importBinary(new File(programPath), languageId, analyze);
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
                return decompileOne(fn, timeoutSeconds);
            }
        } catch (Exception e) {
            return DecompileResult.failure(describe(e));
        }
    }

    @Override
    public void decompileMany(List<String> addresses, boolean all, int timeoutSeconds,
                              BooleanSupplier cancelled, Consumer<DecompileResult> sink) {
        synchronized (lock) {
            if (program == null || decomp == null) {
                sink.accept(DecompileResult.failure("no program open; call OpenProgram first"));
                return;
            }
            if (all) {
                int sinceRecycle = 0;
                for (Function fn : program.getFunctionManager().getFunctions(true)) {
                    if (cancelled.getAsBoolean()) {
                        return;
                    }
                    sink.accept(safeDecompile(fn, timeoutSeconds));
                    // Reset the native decompiler process periodically so its RSS cannot creep unbounded across
                    // a huge binary — this is what keeps each pooled server within a predictable memory budget.
                    // A recycle failure (e.g. the native process cannot be respawned under memory pressure — the
                    // very scenario a large pool creates) must NOT abort the whole stream: end the sweep cleanly so
                    // every function decompiled so far is preserved (the client's onCompleted still fires).
                    if (++sinceRecycle >= DECOMP_RECYCLE_EVERY) {
                        sinceRecycle = 0;
                        if (!recycleDecompiler()) {
                            sink.accept(DecompileResult.failure(
                                    "decompiler recycle failed; ended decompile sweep early with partial results"));
                            return;
                        }
                    }
                }
            } else {
                for (String address : addresses) {
                    if (cancelled.getAsBoolean()) {
                        return;
                    }
                    Function fn = resolveFunction(address, null);
                    sink.accept(fn == null
                            ? DecompileResult.failure("no function found at address " + address)
                            : safeDecompile(fn, timeoutSeconds));
                }
            }
        }
    }

    /** Decompile one function; never throws (errors become a failure result for that function). */
    private DecompileResult safeDecompile(Function fn, int timeoutSeconds) {
        try {
            return decompileOne(fn, timeoutSeconds);
        } catch (Exception e) {
            return DecompileResult.failure(describe(e));
        }
    }

    private DecompileResult decompileOne(Function fn, int timeoutSeconds) {
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

    @Override
    public ListResult listFunctions(boolean includeCalls) {
        try {
            synchronized (lock) {
                if (program == null) {
                    return ListResult.failure("no program open; call OpenProgram first");
                }
                List<FunctionSummary> out = new ArrayList<>(program.getFunctionManager().getFunctionCount());
                for (Function fn : program.getFunctionManager().getFunctions(true)) {
                    List<String> calls = List.of();
                    if (includeCalls) {
                        calls = new ArrayList<>();
                        for (Function callee : fn.getCalledFunctions(TaskMonitor.DUMMY)) {
                            calls.add(callee.getName());
                        }
                    }
                    out.add(new FunctionSummary(
                            fn.getName(),
                            fn.getEntryPoint().toString(),
                            fn.getBody().getNumAddresses(),
                            fn.getParameterCount(),
                            fn.isThunk(),
                            calls));
                }
                return new ListResult(true, out, "");
            }
        } catch (Exception e) {
            return ListResult.failure(describe(e));
        }
    }

    @Override
    public ReferencesResult referencesTo(String address) {
        return references(address, true);
    }

    @Override
    public ReferencesResult referencesFrom(String address) {
        return references(address, false);
    }

    @Override
    public ReferencesResult functionReferences(String address) {
        try {
            synchronized (lock) {
                if (program == null) {
                    return ReferencesResult.failure("no program open; call OpenProgram first");
                }
                Address addr = parseAddress(address);
                if (addr == null) {
                    return ReferencesResult.failure("bad address: " + address);
                }
                Function fn = program.getFunctionManager().getFunctionContaining(addr);
                if (fn == null) {
                    return ReferencesResult.failure("no function at " + address);
                }
                ReferenceManager refs = program.getReferenceManager();
                List<ReferenceSummary> out = new ArrayList<>();
                for (Address a : fn.getBody().getAddresses(true)) {
                    for (Reference ref : refs.getReferencesFrom(a)) {
                        RefType type = ref.getReferenceType();
                        out.add(new ReferenceSummary(
                                ref.getFromAddress().toString(),
                                ref.getToAddress().toString(),
                                type.getName(),
                                type.isCall(),
                                type.isJump(),
                                type.isData(),
                                ref.getOperandIndex(),
                                ref.isPrimary()));
                    }
                }
                return new ReferencesResult(true, out, "");
            }
        } catch (Exception e) {
            return ReferencesResult.failure(describe(e));
        }
    }

    private ReferencesResult references(String address, boolean to) {
        try {
            synchronized (lock) {
                if (program == null) {
                    return ReferencesResult.failure("no program open; call OpenProgram first");
                }
                Address addr = parseAddress(address);
                if (addr == null) {
                    return ReferencesResult.failure("bad address: " + address);
                }
                ReferenceManager refs = program.getReferenceManager();
                List<ReferenceSummary> out = new ArrayList<>();
                Iterable<Reference> found = to
                        ? refs.getReferencesTo(addr)
                        : java.util.Arrays.asList(refs.getReferencesFrom(addr));
                for (Reference ref : found) {
                    RefType type = ref.getReferenceType();
                    out.add(new ReferenceSummary(
                            ref.getFromAddress().toString(),
                            ref.getToAddress().toString(),
                            type.getName(),
                            type.isCall(),
                            type.isJump(),
                            type.isData(),
                            ref.getOperandIndex(),
                            ref.isPrimary()));
                }
                return new ReferencesResult(true, out, "");
            }
        } catch (Exception e) {
            return ReferencesResult.failure(describe(e));
        }
    }

    @Override
    public SymbolsResult listSymbols(boolean includeDynamic, String name) {
        try {
            synchronized (lock) {
                if (program == null) {
                    return SymbolsResult.failure("no program open; call OpenProgram first");
                }
                SymbolTable symbols = program.getSymbolTable();
                Iterable<Symbol> found = (name != null && !name.isBlank())
                        ? symbols.getSymbols(name)
                        : symbols.getAllSymbols(includeDynamic);
                List<SymbolSummary> out = new ArrayList<>();
                for (Symbol s : found) {
                    out.add(toSummary(s));
                }
                return new SymbolsResult(true, out, "");
            }
        } catch (Exception e) {
            return SymbolsResult.failure(describe(e));
        }
    }

    @Override
    public SymbolsResult symbolsAt(String address) {
        try {
            synchronized (lock) {
                if (program == null) {
                    return SymbolsResult.failure("no program open; call OpenProgram first");
                }
                Address addr = parseAddress(address);
                if (addr == null) {
                    return SymbolsResult.failure("bad address: " + address);
                }
                List<SymbolSummary> out = new ArrayList<>();
                for (Symbol s : program.getSymbolTable().getSymbols(addr)) {
                    out.add(toSummary(s));
                }
                return new SymbolsResult(true, out, "");
            }
        } catch (Exception e) {
            return SymbolsResult.failure(describe(e));
        }
    }

    @Override
    public RenameResult renameSymbol(String address, String oldName, String newName) {
        try {
            synchronized (lock) {
                if (program == null) {
                    return RenameResult.failure("no program open; call OpenProgram first");
                }
                if (newName == null || newName.isBlank()) {
                    return RenameResult.failure("new_name is required");
                }

                SymbolTable symbols = program.getSymbolTable();
                Symbol target = null;
                if (address != null && !address.isBlank()) {
                    Address addr = parseAddress(address);
                    if (addr == null) {
                        return RenameResult.failure("bad address: " + address);
                    }
                    target = symbols.getPrimarySymbol(addr);
                    if (target == null) {
                        return RenameResult.failure("no symbol at " + address);
                    }
                } else if (oldName != null && !oldName.isBlank()) {
                    for (Symbol s : symbols.getSymbols(oldName)) {
                        target = s;
                        break;
                    }
                    if (target == null) {
                        return RenameResult.failure("no symbol named " + oldName);
                    }
                } else {
                    return RenameResult.failure("provide an address or old_name");
                }

                int tx = program.startTransaction("GhidraSharp rename");
                boolean committed = false;
                try {
                    target.setName(newName, SourceType.USER_DEFINED);
                    committed = true;
                } finally {
                    program.endTransaction(tx, committed);
                }
                return new RenameResult(true, "", target.getAddress().toString(), target.getName());
            }
        } catch (Exception e) {
            return RenameResult.failure(describe(e));
        }
    }

    private static SymbolSummary toSummary(Symbol s) {
        return new SymbolSummary(
                s.getName(),
                s.getAddress().toString(),
                String.valueOf(s.getSymbolType()),
                String.valueOf(s.getSource()),
                s.isPrimary(),
                s.isGlobal());
    }

    @Override
    public BytesResult readBytes(String address, int length) {
        try {
            synchronized (lock) {
                if (program == null) {
                    return BytesResult.failure("no program open; call OpenProgram first");
                }
                if (length <= 0) {
                    return BytesResult.failure("length must be > 0");
                }
                Address addr = parseAddress(address);
                if (addr == null) {
                    return BytesResult.failure("bad address: " + address);
                }
                int capped = Math.min(length, MAX_READ_BYTES);
                byte[] buf = new byte[capped];
                int read = program.getMemory().getBytes(addr, buf);
                byte[] data = (read == capped) ? buf : java.util.Arrays.copyOf(buf, Math.max(0, read));
                return new BytesResult(true, data, addr.toString(), "");
            }
        } catch (Exception e) {
            return BytesResult.failure(describe(e));
        }
    }

    @Override
    public InstructionsResult instructionsAt(String address, int maxInstructions) {
        try {
            synchronized (lock) {
                if (program == null) {
                    return InstructionsResult.failure("no program open; call OpenProgram first");
                }
                Address addr = parseAddress(address);
                if (addr == null) {
                    return InstructionsResult.failure("bad address: " + address);
                }

                Address end = null;
                int cap;
                if (maxInstructions > 0) {
                    cap = maxInstructions;
                } else {
                    Function fn = program.getFunctionManager().getFunctionContaining(addr);
                    if (fn != null) {
                        end = fn.getBody().getMaxAddress();
                        cap = Integer.MAX_VALUE;
                    } else {
                        cap = DEFAULT_INSTRUCTIONS;
                    }
                }

                List<InstructionInfo> out = new ArrayList<>();
                for (Instruction ins : program.getListing().getInstructions(addr, true)) {
                    if (end != null && ins.getAddress().compareTo(end) > 0) {
                        break;
                    }
                    out.add(toInstruction(ins));
                    if (out.size() >= cap) {
                        break;
                    }
                }
                return new InstructionsResult(true, out, "");
            }
        } catch (Exception e) {
            return InstructionsResult.failure(describe(e));
        }
    }

    private static InstructionInfo toInstruction(Instruction ins) {
        byte[] bytes;
        try {
            bytes = ins.getBytes();
        } catch (Exception e) {
            bytes = new byte[0];
        }
        return new InstructionInfo(
                ins.getAddress().toString(),
                ins.getMnemonicString(),
                ins.toString(),
                bytes,
                ins.getLength());
    }

    @Override
    public OpenResult createProject(String binaryPath, String projectLocation, String projectName,
                                    String languageId, boolean analyze) {
        try {
            ensureInitialized();
            synchronized (lock) {
                closeCurrent();
                File file = new File(binaryPath);
                if (!file.isFile()) {
                    return OpenResult.failure("binary not found: " + binaryPath);
                }

                GhidraProject created = GhidraProject.createProject(projectLocation, projectName, false);
                boolean opened = false;
                try {
                    Program imported = null;
                    try (LoadResults<Program> results = loaderFor(file, languageId)
                            .project(created.getProject())
                            .projectFolderPath("/")
                            .load()) {
                        imported = results.getPrimaryDomainObject(this);
                        if (analyze) {
                            analyzeInTransaction(imported);
                        }
                        results.save(TaskMonitor.DUMMY);   // persist into the new project
                    } finally {
                        if (imported != null) {
                            imported.release(this);        // drop temp consumer; reopen cleanly below
                        }
                    }

                    project = created;
                    program = openProgramFromProject(created, "", true /* writable */);
                    bindDecompiler(program);
                    opened = true;
                    return new OpenResult(
                            true,
                            program.getName(),
                            program.getLanguageID().getIdAsString(),
                            program.getImageBase().getOffset(),
                            program.getFunctionManager().getFunctionCount(),
                            "");
                } finally {
                    if (!opened) {
                        try {
                            created.close();
                        } catch (Exception ignore) {
                            // best effort
                        }
                        project = null;
                        program = null;
                    }
                }
            }
        } catch (Exception e) {
            return OpenResult.failure(describe(e));
        }
    }

    @Override
    public SaveResult saveProgram() {
        try {
            synchronized (lock) {
                if (program == null) {
                    return SaveResult.failure("no program open");
                }
                if (project == null) {
                    return SaveResult.failure("nothing to save to: the program was imported transiently; use CreateProject for a persistent project");
                }
                project.save(program);
                return new SaveResult(true, "");
            }
        } catch (Exception e) {
            return SaveResult.failure(describe(e));
        }
    }

    @Override
    public CommentsResult getComments(String address) {
        try {
            synchronized (lock) {
                if (program == null) {
                    return CommentsResult.failure("no program open; call OpenProgram first");
                }
                Address addr = parseAddress(address);
                if (addr == null) {
                    return CommentsResult.failure("bad address: " + address);
                }
                var listing = program.getListing();
                CommentsInfo info = new CommentsInfo(
                        addr.toString(),
                        nz(listing.getComment(CommentType.EOL, addr)),
                        nz(listing.getComment(CommentType.PRE, addr)),
                        nz(listing.getComment(CommentType.POST, addr)),
                        nz(listing.getComment(CommentType.PLATE, addr)),
                        nz(listing.getComment(CommentType.REPEATABLE, addr)));
                return new CommentsResult(true, info, "");
            }
        } catch (Exception e) {
            return CommentsResult.failure(describe(e));
        }
    }

    @Override
    public AckResult setComment(String address, String type, String comment) {
        try {
            synchronized (lock) {
                if (program == null) {
                    return AckResult.failure("no program open; call OpenProgram first");
                }
                Address addr = parseAddress(address);
                if (addr == null) {
                    return AckResult.failure("bad address: " + address);
                }
                CommentType ct = parseCommentType(type);
                if (ct == null) {
                    return AckResult.failure("bad comment type: " + type + " (EOL|PRE|POST|PLATE|REPEATABLE)");
                }
                int tx = program.startTransaction("SetComment");
                boolean ok = false;
                try {
                    program.getListing().setComment(addr, ct,
                            (comment == null || comment.isEmpty()) ? null : comment);
                    ok = true;
                } finally {
                    program.endTransaction(tx, ok);
                }
                return AckResult.ok();
            }
        } catch (Exception e) {
            return AckResult.failure(describe(e));
        }
    }

    @Override
    public BookmarksResult getBookmarks(String address) {
        try {
            synchronized (lock) {
                if (program == null) {
                    return BookmarksResult.failure("no program open; call OpenProgram first");
                }
                Address addr = parseAddress(address);
                if (addr == null) {
                    return BookmarksResult.failure("bad address: " + address);
                }
                List<BookmarkInfo> out = new ArrayList<>();
                for (Bookmark b : program.getBookmarkManager().getBookmarks(addr)) {
                    out.add(new BookmarkInfo(b.getAddress().toString(), nz(b.getTypeString()),
                            nz(b.getCategory()), nz(b.getComment())));
                }
                return new BookmarksResult(true, out, "");
            }
        } catch (Exception e) {
            return BookmarksResult.failure(describe(e));
        }
    }

    @Override
    public AckResult setBookmark(String address, String type, String category, String comment) {
        try {
            synchronized (lock) {
                if (program == null) {
                    return AckResult.failure("no program open; call OpenProgram first");
                }
                Address addr = parseAddress(address);
                if (addr == null) {
                    return AckResult.failure("bad address: " + address);
                }
                BookmarkManager bm = program.getBookmarkManager();
                int tx = program.startTransaction("SetBookmark");
                boolean ok = false;
                try {
                    bm.setBookmark(addr, nz(type).isEmpty() ? "Note" : type, nz(category), nz(comment));
                    ok = true;
                } finally {
                    program.endTransaction(tx, ok);
                }
                return AckResult.ok();
            }
        } catch (Exception e) {
            return AckResult.failure(describe(e));
        }
    }

    @Override
    public InstructionDetailResult instructionDetail(String address) {
        try {
            synchronized (lock) {
                if (program == null) {
                    return InstructionDetailResult.failure("no program open; call OpenProgram first");
                }
                Address addr = parseAddress(address);
                if (addr == null) {
                    return InstructionDetailResult.failure("bad address: " + address);
                }
                Instruction ins = program.getListing().getInstructionAt(addr);
                if (ins == null) {
                    return InstructionDetailResult.failure("no instruction at " + address);
                }

                List<OperandInfo> operands = new ArrayList<>();
                for (int i = 0; i < ins.getNumOperands(); i++) {
                    var register = ins.getRegister(i);
                    var scalar = ins.getScalar(i);
                    operands.add(new OperandInfo(
                            i,
                            ins.getDefaultOperandRepresentation(i),
                            OperandType.toString(ins.getOperandType(i)),
                            register != null ? register.getName() : "",
                            scalar != null,
                            scalar != null ? scalar.getValue() : 0L));
                }

                List<PcodeOpInfo> pcode = new ArrayList<>();
                for (PcodeOp op : ins.getPcode()) {
                    var output = op.getOutput();
                    List<String> inputs = new ArrayList<>();
                    for (var vn : op.getInputs()) {
                        inputs.add(vn.toString());
                    }
                    pcode.add(new PcodeOpInfo(op.getMnemonic(), output != null ? output.toString() : "", inputs));
                }

                byte[] bytes;
                try {
                    bytes = ins.getBytes();
                } catch (Exception e) {
                    bytes = new byte[0];
                }

                InstructionDetailInfo info = new InstructionDetailInfo(
                        ins.getAddress().toString(), ins.getMnemonicString(), ins.toString(),
                        bytes, ins.getLength(), operands, pcode);
                return new InstructionDetailResult(true, info, "");
            }
        } catch (Exception e) {
            return InstructionDetailResult.failure(describe(e));
        }
    }

    private static CommentType parseCommentType(String type) {
        if (type == null) {
            return null;
        }
        try {
            return CommentType.valueOf(type.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static String nz(String s) {
        return s == null ? "" : s;
    }

    // --- open helpers -------------------------------------------------------

    private void openFromProject(String projectPath, String desiredProgram, boolean writable) throws Exception {
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
        program = openProgramFromProject(project, desiredProgram, writable);
    }

    private static File findProjectFile(File dir) {
        File[] matches = dir.listFiles((d, n) -> n.endsWith(".gpr"));
        return (matches != null && matches.length > 0) ? matches[0] : null;
    }

    private Program openProgramFromProject(GhidraProject project, String desiredProgram, boolean writable) throws Exception {
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
        return project.openProgram(root.getPathname(), chosen.getName(), !writable /* readOnly */);
    }

    private void importBinary(File file, String languageId, boolean analyze) throws Exception {
        // Modern, non-deprecated import (GhidraProject.importProgram is forRemoval).
        // The program is loaded into memory with this engine as its consumer and
        // released in closeCurrent(); no scratch project is created.
        try (LoadResults<Program> results = loaderFor(file, languageId).load()) {
            program = results.getPrimaryDomainObject(this);
        }
        if (analyze) {
            analyzeInTransaction(program);
        }
    }

    private static ProgramLoader.Builder loaderFor(File file, String languageId) {
        ProgramLoader.Builder builder = ProgramLoader.builder().source(file);
        if (languageId != null && !languageId.isBlank()) {
            builder.language(languageId);
        }
        return builder;
    }

    private static void analyzeInTransaction(Program p) {
        // A freshly loaded program needs an open transaction for analyzers to write into it.
        int tx = p.startTransaction("Analysis");
        boolean ok = false;
        try {
            GhidraProject.analyze(p);
            ok = true;
        } finally {
            p.endTransaction(tx, ok);
        }
    }

    @Override
    public FunctionDetailResult getFunction(String address, String name, boolean includeCallers) {
        try {
            synchronized (lock) {
                if (program == null) {
                    return FunctionDetailResult.failure("no program open; call OpenProgram first");
                }
                Function fn = resolveFunction(address, name);
                if (fn == null) {
                    String which = (address != null && !address.isBlank()) ? "address " + address : "name " + name;
                    return FunctionDetailResult.failure("no function found at " + which);
                }

                List<VariableInfo> parameters = new ArrayList<>();
                for (Parameter p : fn.getParameters()) {
                    parameters.add(toVariable(p));
                }
                List<VariableInfo> locals = new ArrayList<>();
                for (Variable v : fn.getLocalVariables()) {
                    locals.add(toVariable(v));
                }
                List<String> callers = List.of();
                if (includeCallers) {
                    callers = new ArrayList<>();
                    for (Function caller : fn.getCallingFunctions(TaskMonitor.DUMMY)) {
                        callers.add(caller.getName());
                    }
                }

                FunctionDetailInfo info = new FunctionDetailInfo(
                        fn.getName(),
                        fn.getEntryPoint().toString(),
                        fn.getPrototypeString(true, false),
                        fn.getReturnType() != null ? fn.getReturnType().getDisplayName() : "",
                        fn.getCallingConventionName(),
                        fn.hasNoReturn(),
                        fn.hasVarArgs(),
                        fn.isInline(),
                        fn.getBody().getNumAddresses(),
                        parameters,
                        locals,
                        callers);
                return new FunctionDetailResult(true, info, "");
            }
        } catch (Exception e) {
            return FunctionDetailResult.failure(describe(e));
        }
    }

    private static VariableInfo toVariable(Variable v) {
        return new VariableInfo(
                v.getName(),
                v.getDataType() != null ? v.getDataType().getDisplayName() : "",
                String.valueOf(v.getVariableStorage()));
    }

    @Override
    public DataResult dataAt(String address) {
        try {
            synchronized (lock) {
                if (program == null) {
                    return DataResult.failure("no program open; call OpenProgram first");
                }
                Address addr = parseAddress(address);
                if (addr == null) {
                    return DataResult.failure("bad address: " + address);
                }
                Data data = program.getListing().getDataAt(addr);
                if (data == null) {
                    return new DataResult(true, new DataItemInfo(addr.toString(), "", 0, "", false, "", false), "");
                }
                return new DataResult(true, toDataItem(data), "");
            }
        } catch (Exception e) {
            return DataResult.failure(describe(e));
        }
    }

    @Override
    public DataTypesResult listDataTypes(String nameContains) {
        try {
            synchronized (lock) {
                if (program == null) {
                    return DataTypesResult.failure("no program open; call OpenProgram first");
                }
                String filter = (nameContains == null) ? "" : nameContains.toLowerCase();
                List<DataTypeSummary> out = new ArrayList<>();
                Iterator<DataType> it = program.getDataTypeManager().getAllDataTypes();
                while (it.hasNext()) {
                    DataType dt = it.next();
                    if (!filter.isEmpty() && !dt.getName().toLowerCase().contains(filter)) {
                        continue;
                    }
                    out.add(new DataTypeSummary(dt.getName(), dt.getDisplayName(), dt.getPathName(),
                            kindOf(dt), dt.getLength()));
                }
                return new DataTypesResult(true, out, "");
            }
        } catch (Exception e) {
            return DataTypesResult.failure(describe(e));
        }
    }

    @Override
    public LanguagesResult listLanguages(String nameContains) {
        try {
            synchronized (lock) {
                ensureInitialized(); // language definitions come from the Ghidra app, not a program
                String filter = (nameContains == null) ? "" : nameContains.toLowerCase();
                List<LanguageInfo> out = new ArrayList<>();
                LanguageService ls = DefaultLanguageService.getLanguageService();
                for (LanguageDescription ld : ls.getLanguageDescriptions(false)) {
                    String id = ld.getLanguageID().getIdAsString();
                    String processor = ld.getProcessor().toString();
                    String endian = ld.getEndian().toString();
                    String variant = ld.getVariant();
                    String description = (ld.getDescription() == null) ? "" : ld.getDescription();
                    if (!filter.isEmpty()
                            && !id.toLowerCase().contains(filter)
                            && !processor.toLowerCase().contains(filter)
                            && !description.toLowerCase().contains(filter)) {
                        continue;
                    }
                    out.add(new LanguageInfo(id, processor, endian, ld.getSize(), variant, description));
                }
                return new LanguagesResult(true, out, "");
            }
        } catch (Exception e) {
            return LanguagesResult.failure(describe(e));
        }
    }

    @Override
    public MemoryBlocksResult listMemoryBlocks() {
        try {
            synchronized (lock) {
                if (program == null) {
                    return MemoryBlocksResult.failure("no program open; call OpenProgram first");
                }
                List<MemoryBlockInfo> out = new ArrayList<>();
                for (ghidra.program.model.mem.MemoryBlock b : program.getMemory().getBlocks()) {
                    out.add(new MemoryBlockInfo(
                            b.getName(),
                            b.getStart().toString(),
                            b.getEnd().toString(),
                            b.getSize(),
                            b.isInitialized(),
                            b.isRead(),
                            b.isWrite(),
                            b.isExecute()));
                }
                return new MemoryBlocksResult(true, out, "");
            }
        } catch (Exception e) {
            return MemoryBlocksResult.failure(describe(e));
        }
    }

    @Override
    public FindStringsResult findStrings(String substring, int limit) {
        try {
            synchronized (lock) {
                if (program == null) {
                    return FindStringsResult.failure("no program open; call OpenProgram first");
                }
                String filter = (substring == null) ? "" : substring.toLowerCase();
                int cap = (limit > 0) ? limit : 200;
                ReferenceManager refMgr = program.getReferenceManager();
                List<FoundStringInfo> out = new ArrayList<>();
                // Iterate the program's DEFINED strings and match on the actual decoded text
                // (not the sanitized s_/u_ label), so multi-word / renamed / imported strings are found.
                for (Data data : DefinedDataIterator.byDataInstance(program, StringDataInstance::isString)) {
                    if (out.size() >= cap) {
                        break;
                    }
                    StringDataInstance sdi = StringDataInstance.getStringDataInstance(data);
                    String text = sdi.getStringValue();
                    if (text == null) {
                        continue;
                    }
                    if (!filter.isEmpty() && !text.toLowerCase().contains(filter)) {
                        continue;
                    }
                    boolean unicode = data.getDataType().getName().toLowerCase().contains("unicode");
                    LinkedHashSet<String> xrefs = new LinkedHashSet<>();
                    for (Reference ref : refMgr.getReferencesTo(data.getAddress())) {
                        xrefs.add(ref.getFromAddress().toString());
                    }
                    out.add(new FoundStringInfo(data.getAddress().toString(), text, unicode, new ArrayList<>(xrefs)));
                }
                return new FindStringsResult(true, out, "");
            }
        } catch (Exception e) {
            return FindStringsResult.failure(describe(e));
        }
    }

    @Override
    public DataResult applyDataType(String address, String dataType) {
        try {
            synchronized (lock) {
                if (program == null) {
                    return DataResult.failure("no program open; call OpenProgram first");
                }
                Address addr = parseAddress(address);
                if (addr == null) {
                    return DataResult.failure("bad address: " + address);
                }
                DataType dt = resolveDataType(dataType);
                if (dt == null) {
                    return DataResult.failure("unknown data type: " + dataType);
                }

                int tx = program.startTransaction("ApplyDataType");
                boolean committed = false;
                try {
                    long len = Math.max(1, dt.getLength());
                    program.getListing().clearCodeUnits(addr, addr.add(len - 1), false);
                    Data data = program.getListing().createData(addr, dt);
                    committed = true;
                    return new DataResult(true, toDataItem(data), "");
                } finally {
                    program.endTransaction(tx, committed);
                }
            }
        } catch (Exception e) {
            return DataResult.failure(describe(e));
        }
    }

    @Override
    public ScriptResult runScript(String scriptPath, List<String> args) {
        synchronized (lock) {
            if (program == null) {
                return ScriptResult.failure("no program open; call OpenProgram first");
            }
            File file = new File(scriptPath);
            if (!file.isFile()) {
                return ScriptResult.failure("script not found: " + scriptPath);
            }
            ghidra.app.plugin.core.osgi.BundleHost bundleHost = GhidraScriptUtil.acquireBundleHostReference();
            try {
                ResourceFile source = new ResourceFile(file);
                // The script's directory must be a known (enabled) source bundle before
                // its provider can compile/load the class.
                ResourceFile scriptDir = source.getParentFile();
                if (scriptDir != null && bundleHost.getGhidraBundle(scriptDir) == null) {
                    bundleHost.add(scriptDir, true, false);
                }
                GhidraScriptProvider provider = GhidraScriptUtil.getProvider(source);
                if (provider == null) {
                    return ScriptResult.failure("no GhidraScript provider for " + scriptPath);
                }
                GhidraScript script = provider.getScriptInstance(source, new PrintWriter(System.out));
                if (args != null && !args.isEmpty()) {
                    script.setScriptArgs(args.toArray(new String[0]));
                }
                GhidraState state = new GhidraState(null, null, program, null, null, null);
                StringWriter out = new StringWriter();
                StringWriter err = new StringWriter();
                ScriptControls controls = new ScriptControls(
                        new PrintWriter(out, true), new PrintWriter(err, true), TaskMonitor.DUMMY);
                script.execute(state, controls);
                return new ScriptResult(true, out.toString(), err.toString(), "");
            } catch (Exception e) {
                return ScriptResult.failure(describe(e));
            } finally {
                GhidraScriptUtil.releaseBundleHostReference();
            }
        }
    }

    private DataType resolveDataType(String name) {
        DataTypeManager dtm = program.getDataTypeManager();
        DataType dt = dtm.getDataType(name);
        if (dt != null) {
            return dt;
        }
        // Handles built-ins ("float"), pointers ("int *"), arrays ("char[16]"), named types.
        try {
            return new ghidra.util.data.DataTypeParser(dtm, dtm, null,
                    ghidra.util.data.DataTypeParser.AllowedDataTypes.ALL).parse(name);
        } catch (Exception e) {
            return null;
        }
    }

    private static DataItemInfo toDataItem(Data data) {
        String target = "";
        if (data.isPointer() && data.getValue() instanceof Address pointed) {
            target = pointed.toString();
        }
        return new DataItemInfo(
                data.getAddress().toString(),
                data.getDataType().getDisplayName(),
                data.getLength(),
                data.getDefaultValueRepresentation(),
                data.isPointer(),
                target,
                true);
    }

    private static String kindOf(DataType dt) {
        if (dt instanceof ghidra.program.model.data.Structure) {
            return "Structure";
        }
        if (dt instanceof ghidra.program.model.data.Enum) {
            return "Enum";
        }
        if (dt instanceof ghidra.program.model.data.TypeDef) {
            return "TypeDef";
        }
        if (dt instanceof ghidra.program.model.data.Union) {
            return "Union";
        }
        if (dt instanceof ghidra.program.model.data.Pointer) {
            return "Pointer";
        }
        if (dt instanceof ghidra.program.model.data.Array) {
            return "Array";
        }
        if (dt instanceof ghidra.program.model.data.BuiltInDataType) {
            return "BuiltIn";
        }
        return "Other";
    }

    // --- decompile helpers --------------------------------------------------

    private Function resolveFunction(String address, String name) {
        if (address != null && !address.isBlank()) {
            Address at = parseAddress(address);
            // Containing, not entry-only: a mid-function address resolves to its function.
            return at == null ? null : program.getFunctionManager().getFunctionContaining(at);
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
        if (address == null || address.isBlank()) {
            return null;
        }
        String s = address.trim();
        // Space-qualified ("ram:00010000", as JVM/Dalvik/Harvard targets use) or a
        // plain default-space address — let the AddressFactory parse it.
        try {
            Address a = program.getAddressFactory().getAddress(s);
            if (a != null) {
                return a;
            }
        } catch (Exception ignore) {
            // fall through to the bare-hex path
        }
        // Bare hex (optionally 0x-prefixed) into the default address space.
        String hex = s.toLowerCase().startsWith("0x") ? s.substring(2) : s;
        try {
            long offset = Long.parseLong(hex, 16);
            return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private void bindDecompiler(Program program) {
        decomp = new DecompInterface();
        // Pin the per-function decompile payload to Ghidra's own suggested default (50 MB) explicitly, so a future
        // Ghidra default change can't silently raise a single server's peak native memory. This equals today's
        // default, so it adds no protection now — the real RSS control is periodic recycling (DECOMP_RECYCLE_EVERY);
        // this is just a belt-and-braces ceiling.
        DecompileOptions options = new DecompileOptions();
        options.setMaxPayloadMBytes(DECOMP_MAX_PAYLOAD_MB);
        // Bound a single monstrous function's native decompiler peak — the only cap that does (see DECOMP_MAX_INSTRUCTIONS).
        options.setMaxInstructions(DECOMP_MAX_INSTRUCTIONS);
        decomp.setOptions(options);
        if (!decomp.openProgram(program)) {
            String msg = decomp.getLastMessage();
            decomp.dispose();
            decomp = null;
            throw new IllegalStateException("decompiler failed to open program: " + msg);
        }
    }

    /**
     * Dispose and rebind the decompiler on the current program, resetting the native decompile.exe process RSS.
     * Best-effort: returns {@code false} (instead of throwing) if the decompiler cannot be rebound, so a recycle
     * failure mid-batch degrades gracefully rather than aborting the whole decompile stream. On failure {@code decomp}
     * is left null, so any subsequent decompile attempt fails per-function via {@link #safeDecompile} rather than hard.
     */
    private boolean recycleDecompiler() {
        if (decomp != null) {
            decomp.dispose();
            decomp = null;
        }
        try {
            bindDecompiler(program);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public void closeProgram() {
        synchronized (lock) {
            closeCurrent();
        }
    }

    private void closeCurrent() {
        if (decomp != null) {
            decomp.dispose();
            decomp = null;
        }
        if (project != null) {
            project.close();   // releases the project-opened program
            project = null;
            program = null;
        } else if (program != null) {
            program.release(this);   // imported via ProgramLoader (this engine is the consumer)
            program = null;
        }
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
