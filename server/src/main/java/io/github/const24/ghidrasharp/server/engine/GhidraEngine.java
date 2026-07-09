package io.github.const24.ghidrasharp.server.engine;

import java.util.List;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

/**
 * The thin Ghidra surface the gRPC service delegates to.
 *
 * <p>Keeping the service free of Ghidra types lets the transport be proven with a
 * {@link StubEngine} and the Ghidra-as-library implementation be dropped in later
 * without touching the wire layer.
 */
public interface GhidraEngine {

    /** Short engine name for logging (e.g. {@code "stub"}, {@code "ghidra-library"}). */
    String name();

    /** Version string reported to clients via {@code Ping} (e.g. the Ghidra release). */
    String ghidraVersion();

    /** Open (importing + analyzing if requested) a program and make it current. */
    OpenResult open(String projectPath, String programPath, String languageId, boolean analyze, boolean writable);

    /** Decompile a function identified by entry address (hex) or name. */
    DecompileResult decompile(String address, String name, int timeoutSeconds);

    /**
     * Batch decompile, pushing each result to {@code sink} as it is produced (so
     * the caller can stream them). When {@code all} is true the whole program is
     * swept; otherwise {@code addresses} (hex entry points) are decompiled. The
     * sweep stops early once {@code cancelled} returns true (e.g. the client
     * disconnected), so a cancelled batch doesn't keep decompiling.
     */
    void decompileMany(List<String> addresses, boolean all, int timeoutSeconds,
                       BooleanSupplier cancelled, Consumer<DecompileResult> sink);

    /** List the functions in the current program (optionally with each one's callees). */
    ListResult listFunctions(boolean includeCalls);

    /** References (xrefs) whose target is {@code address} ("who points here"). */
    ReferencesResult referencesTo(String address);

    /** References (xrefs) originating from {@code address} ("what this points to"). */
    ReferencesResult referencesFrom(String address);

    /** Every reference originating in the body of the function at {@code address}, ordered by from-address. */
    ReferencesResult functionReferences(String address);

    /** List symbols, optionally only those named {@code name}; {@code includeDynamic} adds auto-generated ones. */
    SymbolsResult listSymbols(boolean includeDynamic, String name);

    /** Symbols defined at {@code address}. */
    SymbolsResult symbolsAt(String address);

    /** Rename the symbol at {@code address} (or named {@code oldName}) to {@code newName}; needs a writable program. */
    RenameResult renameSymbol(String address, String oldName, String newName);

    /** Read {@code length} raw bytes of program memory starting at {@code address}. */
    BytesResult readBytes(String address, int length);

    /** Read disassembled instructions from {@code address} ({@code maxInstructions} <= 0 = whole containing function). */
    InstructionsResult instructionsAt(String address, int maxInstructions);

    /** Full detail for one function (by entry address or name): typed signature, params, locals, callers. */
    FunctionDetailResult getFunction(String address, String name, boolean includeCallers);

    /** The defined data item at {@code address} (or an undefined marker if none). */
    DataResult dataAt(String address);

    /** Data types known to the program, optionally filtered by name. */
    DataTypesResult listDataTypes(String nameContains);

    /** Apply {@code dataType} at {@code address}; needs a writable program. */
    DataResult applyDataType(String address, String dataType);

    /** Escape hatch: run a GhidraScript against the current program, capturing stdout/stderr. */
    ScriptResult runScript(String scriptPath, List<String> args);

    /** Import a binary into a new persistent project on disk, analyze, save, and make it current. */
    OpenResult createProject(String binaryPath, String projectLocation, String projectName,
                             String languageId, boolean analyze);

    /** Persist the current (writable, project-backed) program to disk. */
    SaveResult saveProgram();

    /** Close the current program/project, releasing its on-disk lock. No-op if nothing is open. */
    void closeProgram();

    /** All comment types at an address. */
    CommentsResult getComments(String address);

    /** Set (or clear) a comment of {@code type} at an address; needs a writable program. */
    AckResult setComment(String address, String type, String comment);

    /** Bookmarks at an address. */
    BookmarksResult getBookmarks(String address);

    /** Add a bookmark at an address; needs a writable program. */
    AckResult setBookmark(String address, String type, String category, String comment);

    /** One instruction in full: structured operands and raw PCode. */
    InstructionDetailResult instructionDetail(String address);

    /** Processor languages Ghidra supports (optionally filtered by name) — its language picker. */
    LanguagesResult listLanguages(String nameContains);

    /** The program's memory blocks / sections (name, range, size, permissions). */
    MemoryBlocksResult listMemoryBlocks();

    /** Defined strings whose text contains {@code substring} (case-insensitive; empty = all), with xrefs; capped at {@code limit} (&lt;= 0 = default). */
    FindStringsResult findStrings(String substring, int limit);

    /** Result of opening a program. */
    record OpenResult(
            boolean success,
            String programName,
            String languageId,
            long imageBase,
            int functionCount,
            String error) {

        public static OpenResult failure(String error) {
            return new OpenResult(false, "", "", 0L, 0, error);
        }
    }

    /** Result of decompiling a function. */
    record DecompileResult(
            boolean success,
            String cCode,
            String signature,
            String entryAddress,
            String error) {

        public static DecompileResult failure(String error) {
            return new DecompileResult(false, "", "", "", error);
        }
    }

    /** One function's summary, sized for client-side querying. */
    record FunctionSummary(
            String name,
            String entryAddress,
            long size,
            int parameterCount,
            boolean thunk,
            List<String> calls) {
    }

    /** Result of listing functions. */
    record ListResult(boolean success, List<FunctionSummary> functions, String error) {

        public static ListResult failure(String error) {
            return new ListResult(false, List.of(), error);
        }
    }

    /** One cross-reference (xref). */
    record ReferenceSummary(
            String fromAddress,
            String toAddress,
            String referenceType,
            boolean call,
            boolean jump,
            boolean data,
            int operandIndex,
            boolean primary) {
    }

    /** Result of a references query. */
    record ReferencesResult(boolean success, List<ReferenceSummary> references, String error) {

        public static ReferencesResult failure(String error) {
            return new ReferencesResult(false, List.of(), error);
        }
    }

    /** One symbol (a name bound to an address). */
    record SymbolSummary(
            String name,
            String address,
            String symbolType,
            String source,
            boolean primary,
            boolean global) {
    }

    /** Result of a symbols query. */
    record SymbolsResult(boolean success, List<SymbolSummary> symbols, String error) {

        public static SymbolsResult failure(String error) {
            return new SymbolsResult(false, List.of(), error);
        }
    }

    /** Result of a rename. */
    record RenameResult(boolean success, String error, String address, String newName) {

        public static RenameResult failure(String error) {
            return new RenameResult(false, error, "", "");
        }
    }

    /** Result of a raw-bytes read. */
    record BytesResult(boolean success, byte[] data, String address, String error) {

        public static BytesResult failure(String error) {
            return new BytesResult(false, new byte[0], "", error);
        }
    }

    /** One disassembled instruction. */
    record InstructionInfo(
            String address,
            String mnemonic,
            String representation,
            byte[] rawBytes,
            int length) {
    }

    /** Result of a disassembly-listing query. */
    record InstructionsResult(boolean success, List<InstructionInfo> instructions, String error) {

        public static InstructionsResult failure(String error) {
            return new InstructionsResult(false, List.of(), error);
        }
    }

    /** A parameter or local variable. */
    record VariableInfo(String name, String dataType, String storage) {
    }

    /** Full detail for one function. */
    record FunctionDetailInfo(
            String name,
            String entryAddress,
            String signature,
            String returnType,
            String callingConvention,
            boolean noReturn,
            boolean varargs,
            boolean inline,
            long size,
            List<VariableInfo> parameters,
            List<VariableInfo> localVariables,
            List<String> callers) {
    }

    /** Result of a function-detail query. */
    record FunctionDetailResult(boolean success, FunctionDetailInfo function, String error) {

        public static FunctionDetailResult failure(String error) {
            return new FunctionDetailResult(false, null, error);
        }
    }

    /** A defined data item. */
    record DataItemInfo(
            String address,
            String dataType,
            int length,
            String value,
            boolean pointer,
            String pointerTarget,
            boolean defined) {
    }

    /** Result of a data query (GetDataAt / ApplyDataType). */
    record DataResult(boolean success, DataItemInfo data, String error) {

        public static DataResult failure(String error) {
            return new DataResult(false, null, error);
        }
    }

    /** One data type. */
    record DataTypeSummary(String name, String displayName, String path, String kind, int length) {
    }

    /** Result of a data-types query. */
    record DataTypesResult(boolean success, List<DataTypeSummary> dataTypes, String error) {

        public static DataTypesResult failure(String error) {
            return new DataTypesResult(false, List.of(), error);
        }
    }

    /** One processor language Ghidra supports. */
    record LanguageInfo(String id, String processor, String endian, int size, String variant, String description) {
    }

    /** Result of a languages query. */
    record LanguagesResult(boolean success, List<LanguageInfo> languages, String error) {

        public static LanguagesResult failure(String error) {
            return new LanguagesResult(false, List.of(), error);
        }
    }

    /** One memory block / section: name, range, size, permissions. */
    record MemoryBlockInfo(
            String name,
            String start,
            String end,
            long size,
            boolean initialized,
            boolean read,
            boolean write,
            boolean execute) {
    }

    /** Result of listing memory blocks. */
    record MemoryBlocksResult(boolean success, List<MemoryBlockInfo> blocks, String error) {

        public static MemoryBlocksResult failure(String error) {
            return new MemoryBlocksResult(false, List.of(), error);
        }
    }

    /** One defined string and the addresses that reference it. */
    record FoundStringInfo(String address, String text, boolean unicode, List<String> xrefFrom) {
    }

    /** Result of a find-strings query. */
    record FindStringsResult(boolean success, List<FoundStringInfo> strings, String error) {

        public static FindStringsResult failure(String error) {
            return new FindStringsResult(false, List.of(), error);
        }
    }

    /** Result of running a GhidraScript. */
    record ScriptResult(boolean success, String stdout, String stderr, String error) {

        public static ScriptResult failure(String error) {
            return new ScriptResult(false, "", "", error);
        }
    }

    /** Result of saving the current program. */
    record SaveResult(boolean success, String error) {

        public static SaveResult failure(String error) {
            return new SaveResult(false, error);
        }
    }

    /** Generic ack for small mutating calls. */
    record AckResult(boolean success, String error) {

        public static AckResult ok() {
            return new AckResult(true, "");
        }

        public static AckResult failure(String error) {
            return new AckResult(false, error);
        }
    }

    /** Comments at an address (all five types). */
    record CommentsInfo(String address, String eol, String pre, String post, String plate, String repeatable) {
    }

    /** Result of a comments query. */
    record CommentsResult(boolean success, CommentsInfo comments, String error) {

        public static CommentsResult failure(String error) {
            return new CommentsResult(false, null, error);
        }
    }

    /** One bookmark. */
    record BookmarkInfo(String address, String type, String category, String comment) {
    }

    /** Result of a bookmarks query. */
    record BookmarksResult(boolean success, List<BookmarkInfo> bookmarks, String error) {

        public static BookmarksResult failure(String error) {
            return new BookmarksResult(false, List.of(), error);
        }
    }

    /** One instruction operand. */
    record OperandInfo(int index, String representation, String type, String register, boolean hasScalar, long scalar) {
    }

    /** One raw PCode operation. */
    record PcodeOpInfo(String mnemonic, String output, List<String> inputs) {
    }

    /** One instruction in full. */
    record InstructionDetailInfo(
            String address,
            String mnemonic,
            String representation,
            byte[] rawBytes,
            int length,
            List<OperandInfo> operands,
            List<PcodeOpInfo> pcode) {
    }

    /** Result of an instruction-detail query. */
    record InstructionDetailResult(boolean success, InstructionDetailInfo instruction, String error) {

        public static InstructionDetailResult failure(String error) {
            return new InstructionDetailResult(false, null, error);
        }
    }
}
