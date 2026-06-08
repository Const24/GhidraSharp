package io.github.const24.ghidrasharp.server.service;

import io.github.const24.ghidrasharp.proto.DecompileFunctionsRequest;
import io.github.const24.ghidrasharp.proto.DecompileReply;
import io.github.const24.ghidrasharp.proto.DecompileRequest;
import io.github.const24.ghidrasharp.proto.FunctionInfo;
import io.github.const24.ghidrasharp.proto.GhidraSharpServiceGrpc;
import io.github.const24.ghidrasharp.proto.ListFunctionsReply;
import io.github.const24.ghidrasharp.proto.ListFunctionsRequest;
import io.github.const24.ghidrasharp.proto.OpenProgramReply;
import io.github.const24.ghidrasharp.proto.OpenProgramRequest;
import io.github.const24.ghidrasharp.proto.PingReply;
import io.github.const24.ghidrasharp.proto.PingRequest;
import io.github.const24.ghidrasharp.proto.GhidraSymbol;
import io.github.const24.ghidrasharp.proto.ListSymbolsReply;
import io.github.const24.ghidrasharp.proto.ListSymbolsRequest;
import io.github.const24.ghidrasharp.proto.Reference;
import io.github.const24.ghidrasharp.proto.ReferencesReply;
import io.github.const24.ghidrasharp.proto.ReferencesRequest;
import io.github.const24.ghidrasharp.proto.RenameSymbolReply;
import io.github.const24.ghidrasharp.proto.RenameSymbolRequest;
import io.github.const24.ghidrasharp.proto.SymbolsAtRequest;
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
                request.getAnalyze(),
                request.getWritable());

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

        responseObserver.onNext(toReply(r));
        responseObserver.onCompleted();
    }

    @Override
    public void decompileFunctions(DecompileFunctionsRequest request, StreamObserver<DecompileReply> responseObserver) {
        engine.decompileMany(
                request.getAddressesList(),
                request.getAll(),
                request.getTimeoutSeconds(),
                result -> responseObserver.onNext(toReply(result)));
        responseObserver.onCompleted();
    }

    private static DecompileReply toReply(GhidraEngine.DecompileResult r) {
        return DecompileReply.newBuilder()
                .setSuccess(r.success())
                .setCCode(nullToEmpty(r.cCode()))
                .setSignature(nullToEmpty(r.signature()))
                .setEntryAddress(nullToEmpty(r.entryAddress()))
                .setError(nullToEmpty(r.error()))
                .build();
    }

    @Override
    public void listFunctions(ListFunctionsRequest request, StreamObserver<ListFunctionsReply> responseObserver) {
        GhidraEngine.ListResult r = engine.listFunctions(request.getIncludeCalls());

        ListFunctionsReply.Builder reply = ListFunctionsReply.newBuilder()
                .setSuccess(r.success())
                .setError(nullToEmpty(r.error()));

        for (GhidraEngine.FunctionSummary fn : r.functions()) {
            reply.addFunctions(FunctionInfo.newBuilder()
                    .setName(nullToEmpty(fn.name()))
                    .setEntryAddress(nullToEmpty(fn.entryAddress()))
                    .setSize(fn.size())
                    .setParameterCount(fn.parameterCount())
                    .setIsThunk(fn.thunk())
                    .addAllCalls(fn.calls())
                    .build());
        }

        responseObserver.onNext(reply.build());
        responseObserver.onCompleted();
    }

    @Override
    public void getReferencesTo(ReferencesRequest request, StreamObserver<ReferencesReply> responseObserver) {
        respondReferences(engine.referencesTo(request.getAddress()), responseObserver);
    }

    @Override
    public void getReferencesFrom(ReferencesRequest request, StreamObserver<ReferencesReply> responseObserver) {
        respondReferences(engine.referencesFrom(request.getAddress()), responseObserver);
    }

    private static void respondReferences(GhidraEngine.ReferencesResult r, StreamObserver<ReferencesReply> observer) {
        ReferencesReply.Builder reply = ReferencesReply.newBuilder()
                .setSuccess(r.success())
                .setError(nullToEmpty(r.error()));

        for (GhidraEngine.ReferenceSummary ref : r.references()) {
            reply.addReferences(Reference.newBuilder()
                    .setFromAddress(nullToEmpty(ref.fromAddress()))
                    .setToAddress(nullToEmpty(ref.toAddress()))
                    .setReferenceType(nullToEmpty(ref.referenceType()))
                    .setIsCall(ref.call())
                    .setIsJump(ref.jump())
                    .setIsData(ref.data())
                    .setOperandIndex(ref.operandIndex())
                    .setIsPrimary(ref.primary())
                    .build());
        }

        observer.onNext(reply.build());
        observer.onCompleted();
    }

    @Override
    public void listSymbols(ListSymbolsRequest request, StreamObserver<ListSymbolsReply> responseObserver) {
        respondSymbols(engine.listSymbols(request.getIncludeDynamic(), request.getName()), responseObserver);
    }

    @Override
    public void getSymbolsAt(SymbolsAtRequest request, StreamObserver<ListSymbolsReply> responseObserver) {
        respondSymbols(engine.symbolsAt(request.getAddress()), responseObserver);
    }

    @Override
    public void renameSymbol(RenameSymbolRequest request, StreamObserver<RenameSymbolReply> responseObserver) {
        GhidraEngine.RenameResult r = engine.renameSymbol(
                request.getAddress(), request.getOldName(), request.getNewName());
        responseObserver.onNext(RenameSymbolReply.newBuilder()
                .setSuccess(r.success())
                .setError(nullToEmpty(r.error()))
                .setAddress(nullToEmpty(r.address()))
                .setNewName(nullToEmpty(r.newName()))
                .build());
        responseObserver.onCompleted();
    }

    private static void respondSymbols(GhidraEngine.SymbolsResult r, StreamObserver<ListSymbolsReply> observer) {
        ListSymbolsReply.Builder reply = ListSymbolsReply.newBuilder()
                .setSuccess(r.success())
                .setError(nullToEmpty(r.error()));

        for (GhidraEngine.SymbolSummary s : r.symbols()) {
            reply.addSymbols(GhidraSymbol.newBuilder()
                    .setName(nullToEmpty(s.name()))
                    .setAddress(nullToEmpty(s.address()))
                    .setSymbolType(nullToEmpty(s.symbolType()))
                    .setSource(nullToEmpty(s.source()))
                    .setIsPrimary(s.primary())
                    .setIsGlobal(s.global())
                    .build());
        }

        observer.onNext(reply.build());
        observer.onCompleted();
    }

    private static String nullToEmpty(String s) {
        return s == null ? "" : s;
    }
}
