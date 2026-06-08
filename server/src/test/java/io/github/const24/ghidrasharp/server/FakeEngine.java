package io.github.const24.ghidrasharp.server;

import io.github.const24.ghidrasharp.server.engine.GhidraEngine;

import java.util.List;
import java.util.function.Consumer;

/** A {@link GhidraEngine} returning known, canned data — lets the service mapping be tested with no Ghidra. */
final class FakeEngine implements GhidraEngine {

    @Override
    public String name() {
        return "fake";
    }

    @Override
    public String ghidraVersion() {
        return "test-version";
    }

    @Override
    public OpenResult open(String projectPath, String programPath, String languageId, boolean analyze, boolean writable) {
        return new OpenResult(true, "prog.bin", "Toy:LE:32:default", 0x1000L, 7, "");
    }

    @Override
    public OpenResult createProject(String binaryPath, String projectLocation, String projectName,
                                    String languageId, boolean analyze) {
        return new OpenResult(true, "created.bin", "Toy:LE:32:default", 0x2000L, 3, "");
    }

    @Override
    public DecompileResult decompile(String address, String name, int timeoutSeconds) {
        return new DecompileResult(true, "void fn(void) { return; }", "void fn(void)", "00001000", "");
    }

    @Override
    public void decompileMany(List<String> addresses, boolean all, int timeoutSeconds, Consumer<DecompileResult> sink) {
        sink.accept(new DecompileResult(true, "a", "void a(void)", "00001000", ""));
        sink.accept(new DecompileResult(true, "b", "void b(void)", "00002000", ""));
    }

    @Override
    public ListResult listFunctions(boolean includeCalls) {
        return new ListResult(true,
                List.of(new FunctionSummary("fn1", "00001000", 20L, 2, false, List.of("callee_a", "callee_b"))), "");
    }

    @Override
    public ReferencesResult referencesTo(String address) {
        return references();
    }

    @Override
    public ReferencesResult referencesFrom(String address) {
        return references();
    }

    private static ReferencesResult references() {
        return new ReferencesResult(true,
                List.of(new ReferenceSummary("00001100", "00001000", "UNCONDITIONAL_CALL", true, false, false, 0, true)), "");
    }

    @Override
    public SymbolsResult listSymbols(boolean includeDynamic, String name) {
        return symbols();
    }

    @Override
    public SymbolsResult symbolsAt(String address) {
        return symbols();
    }

    private static SymbolsResult symbols() {
        return new SymbolsResult(true,
                List.of(new SymbolSummary("main", "00001000", "Function", "USER_DEFINED", true, true)), "");
    }

    @Override
    public RenameResult renameSymbol(String address, String oldName, String newName) {
        return new RenameResult(true, "", "00001000", newName);
    }

    @Override
    public BytesResult readBytes(String address, int length) {
        return new BytesResult(true, new byte[] {(byte) 0xDE, (byte) 0xAD}, "00001000", "");
    }

    @Override
    public InstructionsResult instructionsAt(String address, int maxInstructions) {
        return new InstructionsResult(true,
                List.of(new InstructionInfo("00001000", "mov", "mov r1,r2", new byte[] {0x12, 0x34}, 2)), "");
    }

    @Override
    public FunctionDetailResult getFunction(String address, String name, boolean includeCallers) {
        return new FunctionDetailResult(true,
                new FunctionDetailInfo("fn1", "00001000", "int fn1(int p)", "int", "__stdcall", false, false, false, 20L,
                        List.of(new VariableInfo("p", "int", "r4:4")),
                        List.of(new VariableInfo("x", "int", "Stack[-0x8]:4")),
                        List.of("caller_a")),
                "");
    }

    @Override
    public DataResult dataAt(String address) {
        return data();
    }

    @Override
    public DataResult applyDataType(String address, String dataType) {
        return data();
    }

    private static DataResult data() {
        return new DataResult(true, new DataItemInfo("00003000", "float", 4, "1.5", false, "", true), "");
    }

    @Override
    public DataTypesResult listDataTypes(String nameContains) {
        return new DataTypesResult(true, List.of(new DataTypeSummary("int", "int", "/int", "BuiltIn", 4)), "");
    }

    @Override
    public ScriptResult runScript(String scriptPath, List<String> args) {
        return new ScriptResult(true, "hello from script", "", "");
    }

    @Override
    public SaveResult saveProgram() {
        return new SaveResult(true, "");
    }

    @Override
    public CommentsResult getComments(String address) {
        return new CommentsResult(true, new CommentsInfo(address, "end of line", "before", "", "banner", ""), "");
    }

    @Override
    public AckResult setComment(String address, String type, String comment) {
        return new AckResult(true, type); // echo the type so the test can assert it
    }

    @Override
    public BookmarksResult getBookmarks(String address) {
        return new BookmarksResult(true, List.of(new BookmarkInfo("00001000", "Note", "cat", "interesting")), "");
    }

    @Override
    public AckResult setBookmark(String address, String type, String category, String comment) {
        return AckResult.ok();
    }

    @Override
    public InstructionDetailResult instructionDetail(String address) {
        return new InstructionDetailResult(true,
                new InstructionDetailInfo("00001000", "mov", "mov r1,#0x10", new byte[] {(byte) 0xAB, (byte) 0xCD}, 2,
                        List.of(new OperandInfo(0, "r1", "register", "r1", false, 0L),
                                new OperandInfo(1, "0x10", "scalar", "", true, 16L)),
                        List.of(new PcodeOpInfo("COPY", "(register, 0x4, 4)", List.of("(const, 0x10, 4)")))),
                "");
    }
}
