package io.github.const24.ghidrasharp.server.engine;

/**
 * Placeholder engine that proves the C# &harr; Java transport before Ghidra is
 * wired in. {@code Ping} works; the rest report "not implemented".
 */
public final class StubEngine implements GhidraEngine {

    @Override
    public String name() {
        return "stub";
    }

    @Override
    public String ghidraVersion() {
        return "stub (no Ghidra loaded)";
    }

    @Override
    public OpenResult open(String projectPath, String programPath, String languageId, boolean analyze) {
        return OpenResult.failure("OpenProgram not implemented yet (StubEngine)");
    }

    @Override
    public DecompileResult decompile(String address, String name, int timeoutSeconds) {
        return DecompileResult.failure("DecompileFunction not implemented yet (StubEngine)");
    }

    @Override
    public ListResult listFunctions(boolean includeCalls) {
        return ListResult.failure("ListFunctions not implemented yet (StubEngine)");
    }

    @Override
    public void decompileMany(java.util.List<String> addresses, boolean all, int timeoutSeconds,
                              java.util.function.Consumer<DecompileResult> sink) {
        sink.accept(DecompileResult.failure("DecompileFunctions not implemented yet (StubEngine)"));
    }

    @Override
    public ReferencesResult referencesTo(String address) {
        return ReferencesResult.failure("GetReferencesTo not implemented yet (StubEngine)");
    }

    @Override
    public ReferencesResult referencesFrom(String address) {
        return ReferencesResult.failure("GetReferencesFrom not implemented yet (StubEngine)");
    }
}
