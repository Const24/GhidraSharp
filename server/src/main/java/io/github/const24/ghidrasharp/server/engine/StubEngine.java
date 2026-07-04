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
    public OpenResult open(String projectPath, String programPath, String languageId, boolean analyze, boolean writable) {
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
                              java.util.function.BooleanSupplier cancelled,
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

    @Override
    public ReferencesResult functionReferences(String address) {
        return ReferencesResult.failure("GetFunctionReferences not implemented yet (StubEngine)");
    }

    @Override
    public SymbolsResult listSymbols(boolean includeDynamic, String name) {
        return SymbolsResult.failure("ListSymbols not implemented yet (StubEngine)");
    }

    @Override
    public SymbolsResult symbolsAt(String address) {
        return SymbolsResult.failure("GetSymbolsAt not implemented yet (StubEngine)");
    }

    @Override
    public RenameResult renameSymbol(String address, String oldName, String newName) {
        return RenameResult.failure("RenameSymbol not implemented yet (StubEngine)");
    }

    @Override
    public BytesResult readBytes(String address, int length) {
        return BytesResult.failure("ReadBytes not implemented yet (StubEngine)");
    }

    @Override
    public InstructionsResult instructionsAt(String address, int maxInstructions) {
        return InstructionsResult.failure("GetInstructions not implemented yet (StubEngine)");
    }

    @Override
    public FunctionDetailResult getFunction(String address, String name, boolean includeCallers) {
        return FunctionDetailResult.failure("GetFunction not implemented yet (StubEngine)");
    }

    @Override
    public DataResult dataAt(String address) {
        return DataResult.failure("GetDataAt not implemented yet (StubEngine)");
    }

    @Override
    public DataTypesResult listDataTypes(String nameContains) {
        return DataTypesResult.failure("ListDataTypes not implemented yet (StubEngine)");
    }

    @Override
    public DataResult applyDataType(String address, String dataType) {
        return DataResult.failure("ApplyDataType not implemented yet (StubEngine)");
    }

    @Override
    public ScriptResult runScript(String scriptPath, java.util.List<String> args) {
        return ScriptResult.failure("RunScript not implemented yet (StubEngine)");
    }

    @Override
    public OpenResult createProject(String binaryPath, String projectLocation, String projectName,
                                    String languageId, boolean analyze) {
        return OpenResult.failure("CreateProject not implemented yet (StubEngine)");
    }

    @Override
    public SaveResult saveProgram() {
        return SaveResult.failure("SaveProgram not implemented yet (StubEngine)");
    }

    @Override
    public void closeProgram() {
        // nothing is ever open
    }

    @Override
    public CommentsResult getComments(String address) {
        return CommentsResult.failure("GetComments not implemented yet (StubEngine)");
    }

    @Override
    public AckResult setComment(String address, String type, String comment) {
        return AckResult.failure("SetComment not implemented yet (StubEngine)");
    }

    @Override
    public BookmarksResult getBookmarks(String address) {
        return BookmarksResult.failure("GetBookmarks not implemented yet (StubEngine)");
    }

    @Override
    public AckResult setBookmark(String address, String type, String category, String comment) {
        return AckResult.failure("SetBookmark not implemented yet (StubEngine)");
    }

    @Override
    public InstructionDetailResult instructionDetail(String address) {
        return InstructionDetailResult.failure("GetInstructionDetail not implemented yet (StubEngine)");
    }

    @Override
    public LanguagesResult listLanguages(String nameContains) {
        return LanguagesResult.failure("ListLanguages not implemented yet (StubEngine)");
    }
}
