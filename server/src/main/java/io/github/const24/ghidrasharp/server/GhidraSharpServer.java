package io.github.const24.ghidrasharp.server;

import io.github.const24.ghidrasharp.server.engine.GhidraEngine;
import io.github.const24.ghidrasharp.server.engine.GhidraLibraryEngine;
import io.github.const24.ghidrasharp.server.engine.StubEngine;
import io.github.const24.ghidrasharp.server.service.GhidraSharpServiceImpl;
import io.grpc.Server;
import io.grpc.ServerBuilder;

import java.io.IOException;

/**
 * Entry point: starts the gRPC server that fronts a {@link GhidraEngine}.
 *
 * <p>The engine defaults to {@link GhidraLibraryEngine} (Ghidra-as-library); set
 * {@code GHIDRASHARP_ENGINE=stub} to run the transport-only {@link StubEngine}.
 */
public final class GhidraSharpServer {

    private static final int DEFAULT_PORT = 50080;

    public static void main(String[] args) throws IOException, InterruptedException {
        int port = resolvePort();
        GhidraEngine engine = resolveEngine();

        Server server = ServerBuilder.forPort(port)
                .addService(new GhidraSharpServiceImpl(engine))
                .build()
                .start();

        System.out.println("[GhidraSharpServer] listening on " + port + " (engine=" + engine.name() + ")");
        Runtime.getRuntime().addShutdownHook(new Thread(server::shutdown, "grpc-shutdown"));
        server.awaitTermination();
    }

    private static GhidraEngine resolveEngine() {
        String which = System.getenv("GHIDRASHARP_ENGINE");
        if (which != null && which.trim().equalsIgnoreCase("stub")) {
            return new StubEngine();
        }
        return new GhidraLibraryEngine();
    }

    private static int resolvePort() {
        String env = System.getenv("GHIDRASHARP_PORT");
        if (env != null && !env.isBlank()) {
            try {
                return Integer.parseInt(env.trim());
            } catch (NumberFormatException ignored) {
                System.err.println("[GhidraSharpServer] bad GHIDRASHARP_PORT='" + env + "', using " + DEFAULT_PORT);
            }
        }
        return DEFAULT_PORT;
    }

    private GhidraSharpServer() {
    }
}
