package io.github.const24.ghidrasharp.server.service;

import io.github.const24.ghidrasharp.proto.DecompileReply;
import io.github.const24.ghidrasharp.proto.DecompileRequest;
import io.github.const24.ghidrasharp.proto.GhidraSharpServiceGrpc;
import io.github.const24.ghidrasharp.proto.OpenProgramReply;
import io.github.const24.ghidrasharp.proto.OpenProgramRequest;
import io.github.const24.ghidrasharp.proto.PingReply;
import io.github.const24.ghidrasharp.proto.PingRequest;
import io.github.const24.ghidrasharp.server.engine.GhidraEngine;
import io.grpc.stub.StreamObserver;

/** Maps the generated gRPC service onto a {@link GhidraEngine}. Wire glue only. */
public final class GhidraSharpServiceImpl extends GhidraSharpServiceGrpc.GhidraSharpServiceImplBase {

    private final GhidraEngine engine;

    public GhidraSharpServiceImpl(GhidraEngine engine) {
        this.engine = engine;
    }

    @Override
    public void ping(PingRequest request, StreamObserver<PingReply> responseObserver) {
        PingReply reply = PingReply.newBuilder()
                .setMessage("pong: " + request.getMessage())
                .setGhidraVersion(engine.ghidraVersion())
                .build();
        responseObserver.onNext(reply);
        responseObserver.onCompleted();
    }

    @Override
    public void openProgram(OpenProgramRequest request, StreamObserver<OpenProgramReply> responseObserver) {
        GhidraEngine.OpenResult r = engine.open(
                request.getProjectPath(),
                request.getProgramPath(),
                request.getLanguageId(),
                request.getAnalyze());

        OpenProgramReply.Builder reply = OpenProgramReply.newBuilder()
                .setSuccess(r.success())
                .setProgramName(nullToEmpty(r.programName()))
                .setLanguageId(nullToEmpty(r.languageId()))
                .setImageBase(r.imageBase())
                .setFunctionCount(r.functionCount())
                .setError(nullToEmpty(r.error()));

        responseObserver.onNext(reply.build());
        responseObserver.onCompleted();
    }

    @Override
    public void decompileFunction(DecompileRequest request, StreamObserver<DecompileReply> responseObserver) {
        GhidraEngine.DecompileResult r = engine.decompile(
                request.getAddress(),
                request.getName(),
                request.getTimeoutSeconds());

        DecompileReply.Builder reply = DecompileReply.newBuilder()
                .setSuccess(r.success())
                .setCCode(nullToEmpty(r.cCode()))
                .setSignature(nullToEmpty(r.signature()))
                .setEntryAddress(nullToEmpty(r.entryAddress()))
                .setError(nullToEmpty(r.error()));

        responseObserver.onNext(reply.build());
        responseObserver.onCompleted();
    }

    private static String nullToEmpty(String s) {
        return s == null ? "" : s;
    }
}
