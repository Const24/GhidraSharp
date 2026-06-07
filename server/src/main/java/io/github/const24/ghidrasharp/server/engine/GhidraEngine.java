package io.github.const24.ghidrasharp.server.engine;

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
    OpenResult open(String projectPath, String programPath, String languageId, boolean analyze);

    /** Decompile a function identified by entry address (hex) or name. */
    DecompileResult decompile(String address, String name, int timeoutSeconds);

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
}
