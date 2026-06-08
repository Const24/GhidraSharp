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
import com.google.protobuf.ByteString;
import io.github.const24.ghidrasharp.proto.AckReply;
import io.github.const24.ghidrasharp.proto.ApplyDataTypeRequest;
import io.github.const24.ghidrasharp.proto.Bookmark;
import io.github.const24.ghidrasharp.proto.BookmarksReply;
import io.github.const24.ghidrasharp.proto.BookmarksRequest;
import io.github.const24.ghidrasharp.proto.CommentsReply;
import io.github.const24.ghidrasharp.proto.CommentsRequest;
import io.github.const24.ghidrasharp.proto.CreateProjectRequest;
import io.github.const24.ghidrasharp.proto.InstructionDetail;
import io.github.const24.ghidrasharp.proto.InstructionDetailReply;
import io.github.const24.ghidrasharp.proto.InstructionDetailRequest;
import io.github.const24.ghidrasharp.proto.Operand;
import io.github.const24.ghidrasharp.proto.PcodeOp;
import io.github.const24.ghidrasharp.proto.SetBookmarkRequest;
import io.github.const24.ghidrasharp.proto.SetCommentRequest;
import io.github.const24.ghidrasharp.proto.DataAtRequest;
import io.github.const24.ghidrasharp.proto.DataItem;
import io.github.const24.ghidrasharp.proto.DataReply;
import io.github.const24.ghidrasharp.proto.DataTypeInfo;
import io.github.const24.ghidrasharp.proto.DataTypesReply;
import io.github.const24.ghidrasharp.proto.DataTypesRequest;
import io.github.const24.ghidrasharp.proto.LanguageDescriptor;
import io.github.const24.ghidrasharp.proto.ListLanguagesReply;
import io.github.const24.ghidrasharp.proto.ListLanguagesRequest;
import io.github.const24.ghidrasharp.proto.FunctionDetail;
import io.github.const24.ghidrasharp.proto.FunctionDetailReply;
import io.github.const24.ghidrasharp.proto.FunctionRequest;
import io.github.const24.ghidrasharp.proto.GhidraSymbol;
import io.github.const24.ghidrasharp.proto.Instruction;
import io.github.const24.ghidrasharp.proto.InstructionsReply;
import io.github.const24.ghidrasharp.proto.InstructionsRequest;
import io.github.const24.ghidrasharp.proto.ListSymbolsReply;
import io.github.const24.ghidrasharp.proto.ListSymbolsRequest;
import io.github.const24.ghidrasharp.proto.Reference;
import io.github.const24.ghidrasharp.proto.ReferencesReply;
import io.github.const24.ghidrasharp.proto.ReferencesRequest;
import io.github.const24.ghidrasharp.proto.ReadBytesReply;
import io.github.const24.ghidrasharp.proto.ReadBytesRequest;
import io.github.const24.ghidrasharp.proto.RunScriptReply;
import io.github.const24.ghidrasharp.proto.RunScriptRequest;
import io.github.const24.ghidrasharp.proto.SaveProgramReply;
import io.github.const24.ghidrasharp.proto.SaveProgramRequest;
import io.github.const24.ghidrasharp.proto.RenameSymbolReply;
import io.github.const24.ghidrasharp.proto.RenameSymbolRequest;
import io.github.const24.ghidrasharp.proto.SymbolsAtRequest;
import io.github.const24.ghidrasharp.proto.Variable;
import io.github.const24.ghidrasharp.server.engine.GhidraEngine;
import io.grpc.stub.ServerCallStreamObserver;
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
        // Server-streaming: the observer exposes client cancellation so a batch can
        // stop early instead of decompiling the whole program after a disconnect.
        ServerCallStreamObserver<DecompileReply> observer = (ServerCallStreamObserver<DecompileReply>) responseObserver;
        engine.decompileMany(
                request.getAddressesList(),
                request.getAll(),
                request.getTimeoutSeconds(),
                observer::isCancelled,
                result -> observer.onNext(toReply(result)));
        if (!observer.isCancelled()) {
            observer.onCompleted();
        }
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

    @Override
    public void readBytes(ReadBytesRequest request, StreamObserver<ReadBytesReply> responseObserver) {
        GhidraEngine.BytesResult r = engine.readBytes(request.getAddress(), request.getLength());
        responseObserver.onNext(ReadBytesReply.newBuilder()
                .setSuccess(r.success())
                .setData(ByteString.copyFrom(r.data()))
                .setAddress(nullToEmpty(r.address()))
                .setError(nullToEmpty(r.error()))
                .build());
        responseObserver.onCompleted();
    }

    @Override
    public void getInstructions(InstructionsRequest request, StreamObserver<InstructionsReply> responseObserver) {
        GhidraEngine.InstructionsResult r = engine.instructionsAt(request.getAddress(), request.getMaxInstructions());

        InstructionsReply.Builder reply = InstructionsReply.newBuilder()
                .setSuccess(r.success())
                .setError(nullToEmpty(r.error()));

        for (GhidraEngine.InstructionInfo i : r.instructions()) {
            reply.addInstructions(Instruction.newBuilder()
                    .setAddress(nullToEmpty(i.address()))
                    .setMnemonic(nullToEmpty(i.mnemonic()))
                    .setRepresentation(nullToEmpty(i.representation()))
                    .setRawBytes(ByteString.copyFrom(i.rawBytes()))
                    .setLength(i.length())
                    .build());
        }

        responseObserver.onNext(reply.build());
        responseObserver.onCompleted();
    }

    @Override
    public void getFunction(FunctionRequest request, StreamObserver<FunctionDetailReply> responseObserver) {
        GhidraEngine.FunctionDetailResult r = engine.getFunction(
                request.getAddress(), request.getName(), request.getIncludeCallers());

        FunctionDetailReply.Builder reply = FunctionDetailReply.newBuilder()
                .setSuccess(r.success())
                .setError(nullToEmpty(r.error()));

        if (r.success() && r.function() != null) {
            GhidraEngine.FunctionDetailInfo f = r.function();
            FunctionDetail.Builder detail = FunctionDetail.newBuilder()
                    .setName(nullToEmpty(f.name()))
                    .setEntryAddress(nullToEmpty(f.entryAddress()))
                    .setSignature(nullToEmpty(f.signature()))
                    .setReturnType(nullToEmpty(f.returnType()))
                    .setCallingConvention(nullToEmpty(f.callingConvention()))
                    .setNoReturn(f.noReturn())
                    .setVarargs(f.varargs())
                    .setInline(f.inline())
                    .setSize(f.size())
                    .addAllCallers(f.callers());
            for (GhidraEngine.VariableInfo v : f.parameters()) {
                detail.addParameters(toVariable(v));
            }
            for (GhidraEngine.VariableInfo v : f.localVariables()) {
                detail.addLocalVariables(toVariable(v));
            }
            reply.setFunction(detail.build());
        }

        responseObserver.onNext(reply.build());
        responseObserver.onCompleted();
    }

    private static Variable toVariable(GhidraEngine.VariableInfo v) {
        return Variable.newBuilder()
                .setName(nullToEmpty(v.name()))
                .setDataType(nullToEmpty(v.dataType()))
                .setStorage(nullToEmpty(v.storage()))
                .build();
    }

    @Override
    public void getDataAt(DataAtRequest request, StreamObserver<DataReply> responseObserver) {
        respondData(engine.dataAt(request.getAddress()), responseObserver);
    }

    @Override
    public void applyDataType(ApplyDataTypeRequest request, StreamObserver<DataReply> responseObserver) {
        respondData(engine.applyDataType(request.getAddress(), request.getDataType()), responseObserver);
    }

    @Override
    public void listDataTypes(DataTypesRequest request, StreamObserver<DataTypesReply> responseObserver) {
        GhidraEngine.DataTypesResult r = engine.listDataTypes(request.getNameContains());
        DataTypesReply.Builder reply = DataTypesReply.newBuilder()
                .setSuccess(r.success())
                .setError(nullToEmpty(r.error()));
        for (GhidraEngine.DataTypeSummary dt : r.dataTypes()) {
            reply.addDataTypes(DataTypeInfo.newBuilder()
                    .setName(nullToEmpty(dt.name()))
                    .setDisplayName(nullToEmpty(dt.displayName()))
                    .setPath(nullToEmpty(dt.path()))
                    .setKind(nullToEmpty(dt.kind()))
                    .setLength(dt.length())
                    .build());
        }
        responseObserver.onNext(reply.build());
        responseObserver.onCompleted();
    }

    @Override
    public void listLanguages(ListLanguagesRequest request, StreamObserver<ListLanguagesReply> responseObserver) {
        GhidraEngine.LanguagesResult r = engine.listLanguages(request.getNameContains());
        ListLanguagesReply.Builder reply = ListLanguagesReply.newBuilder()
                .setSuccess(r.success())
                .setError(nullToEmpty(r.error()));
        for (GhidraEngine.LanguageInfo l : r.languages()) {
            reply.addLanguages(LanguageDescriptor.newBuilder()
                    .setId(nullToEmpty(l.id()))
                    .setProcessor(nullToEmpty(l.processor()))
                    .setEndian(nullToEmpty(l.endian()))
                    .setSize(l.size())
                    .setVariant(nullToEmpty(l.variant()))
                    .setDescription(nullToEmpty(l.description()))
                    .build());
        }
        responseObserver.onNext(reply.build());
        responseObserver.onCompleted();
    }

    @Override
    public void runScript(RunScriptRequest request, StreamObserver<RunScriptReply> responseObserver) {
        GhidraEngine.ScriptResult r = engine.runScript(request.getScriptPath(), request.getArgsList());
        responseObserver.onNext(RunScriptReply.newBuilder()
                .setSuccess(r.success())
                .setStdout(nullToEmpty(r.stdout()))
                .setStderr(nullToEmpty(r.stderr()))
                .setError(nullToEmpty(r.error()))
                .build());
        responseObserver.onCompleted();
    }

    private static void respondData(GhidraEngine.DataResult r, StreamObserver<DataReply> observer) {
        DataReply.Builder reply = DataReply.newBuilder()
                .setSuccess(r.success())
                .setError(nullToEmpty(r.error()));
        if (r.data() != null) {
            GhidraEngine.DataItemInfo d = r.data();
            reply.setData(DataItem.newBuilder()
                    .setAddress(nullToEmpty(d.address()))
                    .setDataType(nullToEmpty(d.dataType()))
                    .setLength(d.length())
                    .setValue(nullToEmpty(d.value()))
                    .setIsPointer(d.pointer())
                    .setPointerTarget(nullToEmpty(d.pointerTarget()))
                    .setDefined(d.defined())
                    .build());
        }
        observer.onNext(reply.build());
        observer.onCompleted();
    }

    @Override
    public void createProject(CreateProjectRequest request, StreamObserver<OpenProgramReply> responseObserver) {
        GhidraEngine.OpenResult r = engine.createProject(
                request.getBinaryPath(),
                request.getProjectLocation(),
                request.getProjectName(),
                request.getLanguageId(),
                request.getAnalyze());

        responseObserver.onNext(OpenProgramReply.newBuilder()
                .setSuccess(r.success())
                .setProgramName(nullToEmpty(r.programName()))
                .setLanguageId(nullToEmpty(r.languageId()))
                .setImageBase(r.imageBase())
                .setFunctionCount(r.functionCount())
                .setError(nullToEmpty(r.error()))
                .build());
        responseObserver.onCompleted();
    }

    @Override
    public void saveProgram(SaveProgramRequest request, StreamObserver<SaveProgramReply> responseObserver) {
        GhidraEngine.SaveResult r = engine.saveProgram();
        responseObserver.onNext(SaveProgramReply.newBuilder()
                .setSuccess(r.success())
                .setError(nullToEmpty(r.error()))
                .build());
        responseObserver.onCompleted();
    }

    @Override
    public void getComments(CommentsRequest request, StreamObserver<CommentsReply> responseObserver) {
        GhidraEngine.CommentsResult r = engine.getComments(request.getAddress());
        CommentsReply.Builder reply = CommentsReply.newBuilder()
                .setSuccess(r.success())
                .setError(nullToEmpty(r.error()));
        if (r.comments() != null) {
            GhidraEngine.CommentsInfo c = r.comments();
            reply.setAddress(nullToEmpty(c.address()))
                    .setEol(nullToEmpty(c.eol()))
                    .setPre(nullToEmpty(c.pre()))
                    .setPost(nullToEmpty(c.post()))
                    .setPlate(nullToEmpty(c.plate()))
                    .setRepeatable(nullToEmpty(c.repeatable()));
        }
        responseObserver.onNext(reply.build());
        responseObserver.onCompleted();
    }

    @Override
    public void setComment(SetCommentRequest request, StreamObserver<AckReply> responseObserver) {
        respondAck(engine.setComment(request.getAddress(), request.getType(), request.getComment()), responseObserver);
    }

    @Override
    public void getBookmarks(BookmarksRequest request, StreamObserver<BookmarksReply> responseObserver) {
        GhidraEngine.BookmarksResult r = engine.getBookmarks(request.getAddress());
        BookmarksReply.Builder reply = BookmarksReply.newBuilder()
                .setSuccess(r.success())
                .setError(nullToEmpty(r.error()));
        for (GhidraEngine.BookmarkInfo b : r.bookmarks()) {
            reply.addBookmarks(Bookmark.newBuilder()
                    .setAddress(nullToEmpty(b.address()))
                    .setType(nullToEmpty(b.type()))
                    .setCategory(nullToEmpty(b.category()))
                    .setComment(nullToEmpty(b.comment()))
                    .build());
        }
        responseObserver.onNext(reply.build());
        responseObserver.onCompleted();
    }

    @Override
    public void setBookmark(SetBookmarkRequest request, StreamObserver<AckReply> responseObserver) {
        respondAck(engine.setBookmark(request.getAddress(), request.getType(),
                request.getCategory(), request.getComment()), responseObserver);
    }

    @Override
    public void getInstructionDetail(InstructionDetailRequest request,
                                     StreamObserver<InstructionDetailReply> responseObserver) {
        GhidraEngine.InstructionDetailResult r = engine.instructionDetail(request.getAddress());
        InstructionDetailReply.Builder reply = InstructionDetailReply.newBuilder()
                .setSuccess(r.success())
                .setError(nullToEmpty(r.error()));
        if (r.instruction() != null) {
            GhidraEngine.InstructionDetailInfo d = r.instruction();
            InstructionDetail.Builder detail = InstructionDetail.newBuilder()
                    .setAddress(nullToEmpty(d.address()))
                    .setMnemonic(nullToEmpty(d.mnemonic()))
                    .setRepresentation(nullToEmpty(d.representation()))
                    .setRawBytes(ByteString.copyFrom(d.rawBytes()))
                    .setLength(d.length());
            for (GhidraEngine.OperandInfo o : d.operands()) {
                detail.addOperands(Operand.newBuilder()
                        .setIndex(o.index())
                        .setRepresentation(nullToEmpty(o.representation()))
                        .setType(nullToEmpty(o.type()))
                        .setRegister(nullToEmpty(o.register()))
                        .setHasScalar(o.hasScalar())
                        .setScalar(o.scalar())
                        .build());
            }
            for (GhidraEngine.PcodeOpInfo p : d.pcode()) {
                detail.addPcode(PcodeOp.newBuilder()
                        .setMnemonic(nullToEmpty(p.mnemonic()))
                        .setOutput(nullToEmpty(p.output()))
                        .addAllInputs(p.inputs())
                        .build());
            }
            reply.setInstruction(detail.build());
        }
        responseObserver.onNext(reply.build());
        responseObserver.onCompleted();
    }

    private static void respondAck(GhidraEngine.AckResult r, StreamObserver<AckReply> observer) {
        observer.onNext(AckReply.newBuilder()
                .setSuccess(r.success())
                .setError(nullToEmpty(r.error()))
                .build());
        observer.onCompleted();
    }

    private static String nullToEmpty(String s) {
        return s == null ? "" : s;
    }
}
