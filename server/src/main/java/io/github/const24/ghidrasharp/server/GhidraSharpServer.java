package io.github.const24.ghidrasharp.server;

import io.github.const24.ghidrasharp.server.engine.GhidraEngine;
import io.github.const24.ghidrasharp.server.engine.GhidraLibraryEngine;
import io.github.const24.ghidrasharp.server.engine.StubEngine;
import io.github.const24.ghidrasharp.server.service.GhidraSharpServiceImpl;
import io.grpc.Server;
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;

/**
 * Entry point: starts the gRPC server that fronts a {@link GhidraEngine}.
 *
 * <p>The engine defaults to {@link GhidraLibraryEngine} (Ghidra-as-library); set
 * {@code GHIDRASHARP_ENGINE=stub} to run the transport-only {@link StubEngine}.
 *
 * <p>The server binds <b>loopback only</b>: it is unauthenticated and exposes
 * RunScript (arbitrary GhidraScript) plus file/memory access, so it must never be
 * reachable off the host.
 */
public final class GhidraSharpServer {

    private static final int DEFAULT_PORT = 50080;
    private static final int MAX_MESSAGE_BYTES = 256 * 1024 * 1024;

    public static void main(String[] args) throws IOException, InterruptedException {
        int port = resolvePort();
        GhidraEngine engine = resolveEngine();

        Server server = NettyServerBuilder
                .forAddress(new InetSocketAddress(InetAddress.getLoopbackAddress(), port))
                .maxInboundMessageSize(MAX_MESSAGE_BYTES)
                .addService(new GhidraSharpServiceImpl(engine))
                .build()
                .start();

        System.out.println("[GhidraSharpServer] listening on 127.0.0.1:" + port + " (engine=" + engine.name() + ")");
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
