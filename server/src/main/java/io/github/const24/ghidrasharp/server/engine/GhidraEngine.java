package io.github.const24.ghidrasharp.server.engine;

import java.util.List;
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
     * swept; otherwise {@code addresses} (hex entry points) are decompiled.
     */
    void decompileMany(List<String> addresses, boolean all, int timeoutSeconds, Consumer<DecompileResult> sink);

    /** List the functions in the current program (optionally with each one's callees). */
    ListResult listFunctions(boolean includeCalls);

    /** References (xrefs) whose target is {@code address} ("who points here"). */
    ReferencesResult referencesTo(String address);

    /** References (xrefs) originating from {@code address} ("what this points to"). */
    ReferencesResult referencesFrom(String address);

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
}
