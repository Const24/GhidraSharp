using System.Globalization;
using Const24.GhidraSharp.Protocol;
using Google.Protobuf;
using Grpc.Core;
using ProtoSvc = Const24.GhidraSharp.Protocol.GhidraSharpService;

namespace Const24.GhidraSharp.Tests;

/// <summary>
/// A fake server returning known, canned data for every RPC. The contract tests
/// assert that <see cref="GhidraClient"/> maps these wire values to the right
/// public records.
/// </summary>
internal sealed class HappyFake : ProtoSvc.GhidraSharpServiceBase
{
    public override Task<PingReply> Ping(PingRequest request, ServerCallContext context) =>
        Task.FromResult(new PingReply { Message = "pong", GhidraVersion = "test-version", ServerVersion = "test-server" });

    public override Task<OpenProgramReply> OpenProgram(OpenProgramRequest request, ServerCallContext context) =>
        Task.FromResult(new OpenProgramReply
        {
            Success = true,
            ProgramName = "prog.bin",
            LanguageId = "Toy:LE:32:default",
            ImageBase = 0x1000,
            FunctionCount = 7,
        });

    public override Task<OpenProgramReply> CreateProject(CreateProjectRequest request, ServerCallContext context) =>
        Task.FromResult(new OpenProgramReply
        {
            Success = true,
            ProgramName = "created.bin",
            LanguageId = "Toy:LE:32:default",
            ImageBase = 0x2000,
            FunctionCount = 3,
        });

    public override Task<DecompileReply> DecompileFunction(DecompileRequest request, ServerCallContext context) =>
        Task.FromResult(new DecompileReply
        {
            Success = true,
            CCode = "void fn(void) { return; }\n",
            Signature = "void fn(void)",
            EntryAddress = "00001000",
        });

    public override async Task DecompileFunctions(DecompileFunctionsRequest request,
        IServerStreamWriter<DecompileReply> responseStream, ServerCallContext context)
    {
        await responseStream.WriteAsync(new DecompileReply
        { Success = true, CCode = "a\n", Signature = "void a(void)", EntryAddress = "00001000" });
        await responseStream.WriteAsync(new DecompileReply
        { Success = true, CCode = "b\n", Signature = "void b(void)", EntryAddress = "00002000" });
    }

    public override Task<ListFunctionsReply> ListFunctions(ListFunctionsRequest request, ServerCallContext context)
    {
        var reply = new ListFunctionsReply { Success = true };
        reply.Functions.Add(new FunctionInfo
        {
            Name = "fn1",
            EntryAddress = "00001000",
            Size = 20,
            ParameterCount = 2,
            IsThunk = false,
            Calls = { "callee_a", "callee_b" },
        });
        return Task.FromResult(reply);
    }

    public override Task<FunctionDetailReply> GetFunction(FunctionRequest request, ServerCallContext context) =>
        Task.FromResult(new FunctionDetailReply
        {
            Success = true,
            Function = new Protocol.FunctionDetail
            {
                Name = "fn1",
                EntryAddress = "00001000",
                Signature = "int fn1(int p)",
                ReturnType = "int",
                CallingConvention = "__stdcall",
                NoReturn = false,
                Varargs = false,
                Inline = false,
                Size = 20,
                Parameters = { new Variable { Name = "p", DataType = "int", Storage = "r4:4" } },
                LocalVariables = { new Variable { Name = "x", DataType = "int", Storage = "Stack[-0x8]:4" } },
                Callers = { "caller_a" },
            },
        });

    private static ReferencesReply Refs()
    {
        var reply = new ReferencesReply { Success = true };
        reply.References.Add(new Reference
        {
            FromAddress = "00001100",
            ToAddress = "00001000",
            ReferenceType = "UNCONDITIONAL_CALL",
            IsCall = true,
            IsJump = false,
            IsData = false,
            OperandIndex = 0,
            IsPrimary = true,
        });
        return reply;
    }

    public override Task<ReferencesReply> GetReferencesTo(ReferencesRequest request, ServerCallContext context) =>
        Task.FromResult(Refs());

    public override Task<ReferencesReply> GetReferencesFrom(ReferencesRequest request, ServerCallContext context) =>
        Task.FromResult(Refs());

    public override Task<ReferencesReply> GetFunctionReferences(ReferencesRequest request, ServerCallContext context) =>
        Task.FromResult(Refs());

    public override Task<AckReply> CloseProgram(CloseProgramRequest request, ServerCallContext context) =>
        Task.FromResult(new AckReply { Success = true });

    private static ListSymbolsReply Symbols()
    {
        var reply = new ListSymbolsReply { Success = true };
        reply.Symbols.Add(new Protocol.GhidraSymbol
        {
            Name = "main",
            Address = "00001000",
            SymbolType = "Function",
            Source = "USER_DEFINED",
            IsPrimary = true,
            IsGlobal = true,
        });
        return reply;
    }

    public override Task<ListSymbolsReply> ListSymbols(ListSymbolsRequest request, ServerCallContext context) =>
        Task.FromResult(Symbols());

    public override Task<ListSymbolsReply> GetSymbolsAt(SymbolsAtRequest request, ServerCallContext context) =>
        Task.FromResult(Symbols());

    public override Task<RenameSymbolReply> RenameSymbol(RenameSymbolRequest request, ServerCallContext context) =>
        Task.FromResult(new RenameSymbolReply { Success = true, Address = request.Address, NewName = request.NewName });

    private static DataReply Data() =>
        new()
        {
            Success = true,
            Data = new Protocol.DataItem
            {
                Address = "00003000",
                DataType = "float",
                Length = 4,
                Value = "1.5",
                IsPointer = false,
                PointerTarget = "",
                Defined = true,
            },
        };

    public override Task<DataReply> GetDataAt(DataAtRequest request, ServerCallContext context) =>
        Task.FromResult(Data());

    public override Task<DataReply> ApplyDataType(ApplyDataTypeRequest request, ServerCallContext context) =>
        Task.FromResult(Data());

    public override Task<DataTypesReply> ListDataTypes(DataTypesRequest request, ServerCallContext context)
    {
        var reply = new DataTypesReply { Success = true };
        reply.DataTypes.Add(new DataTypeInfo
        { Name = "int", DisplayName = "int", Path = "/int", Kind = "BuiltIn", Length = 4 });
        return Task.FromResult(reply);
    }

    public override Task<InstructionsReply> GetInstructions(InstructionsRequest request, ServerCallContext context)
    {
        var reply = new InstructionsReply { Success = true };
        reply.Instructions.Add(new Protocol.Instruction
        {
            Address = "00001000",
            Mnemonic = "mov",
            Representation = "mov r1,r2",
            RawBytes = ByteString.CopyFrom(0x12, 0x34),
            Length = 2,
        });
        return Task.FromResult(reply);
    }

    public override Task<InstructionDetailReply> GetInstructionDetail(InstructionDetailRequest request, ServerCallContext context) =>
        Task.FromResult(new InstructionDetailReply
        {
            Success = true,
            Instruction = new Protocol.InstructionDetail
            {
                Address = "00001000",
                Mnemonic = "mov",
                Representation = "mov r1,#0x10",
                RawBytes = ByteString.CopyFrom(0xAB, 0xCD),
                Length = 2,
                Operands =
                {
                    new Protocol.Operand { Index = 0, Representation = "r1", Type = "register", Register = "r1", HasScalar = false, Scalar = 0 },
                    new Protocol.Operand { Index = 1, Representation = "0x10", Type = "scalar", Register = "", HasScalar = true, Scalar = 16 },
                },
                Pcode =
                {
                    new Protocol.PcodeOp { Mnemonic = "COPY", Output = "(register, 0x4, 4)", Inputs = { "(const, 0x10, 4)" } },
                },
            },
        });

    public override Task<CommentsReply> GetComments(CommentsRequest request, ServerCallContext context) =>
        Task.FromResult(new CommentsReply
        {
            Success = true,
            Address = request.Address,
            Eol = "end of line",
            Pre = "before",
            Post = "",
            Plate = "banner",
            Repeatable = "",
        });

    public override Task<AckReply> SetComment(SetCommentRequest request, ServerCallContext context) =>
        Task.FromResult(new AckReply { Success = true });

    public override Task<BookmarksReply> GetBookmarks(BookmarksRequest request, ServerCallContext context)
    {
        var reply = new BookmarksReply { Success = true };
        reply.Bookmarks.Add(new Bookmark
        { Address = "00001000", Type = "Note", Category = "cat", Comment = "interesting" });
        return Task.FromResult(reply);
    }

    public override Task<AckReply> SetBookmark(SetBookmarkRequest request, ServerCallContext context) =>
        Task.FromResult(new AckReply { Success = true });

    public override Task<SaveProgramReply> SaveProgram(SaveProgramRequest request, ServerCallContext context) =>
        Task.FromResult(new SaveProgramReply { Success = true });

    public override Task<RunScriptReply> RunScript(RunScriptRequest request, ServerCallContext context) =>
        Task.FromResult(new RunScriptReply { Success = true, Stdout = "hello from script", Stderr = "" });

    public override Task<ReadBytesReply> ReadBytes(ReadBytesRequest request, ServerCallContext context) =>
#pragma warning disable IDE0230 // a u8 literal ("ޭ") would hide that the wire bytes are DE AD
        Task.FromResult(new ReadBytesReply { Success = true, Data = ByteString.CopyFrom(0xDE, 0xAD), Address = "00001000" });
#pragma warning restore IDE0230

    public override Task<ListLanguagesReply> ListLanguages(ListLanguagesRequest request, ServerCallContext context) =>
        Task.FromResult(new ListLanguagesReply
        {
            Success = true,
            Languages =
            {
                new LanguageDescriptor
                {
                    Id = "SuperH:BE:32:SH-2A", Processor = "SuperH", Endian = "big",
                    Size = 32, Variant = "SH-2A", Description = "SuperH SH-2A",
                },
            },
        });

    public override Task<ListMemoryBlocksReply> ListMemoryBlocks(ListMemoryBlocksRequest request, ServerCallContext context)
    {
        var reply = new ListMemoryBlocksReply { Success = true };
        reply.Blocks.Add(new MemoryBlockInfo
        {
            Name = ".text",
            Start = "00001000",
            End = "00001fff",
            Size = 4096,
            Initialized = true,
            Read = true,
            Write = false,
            Execute = true,
        });
        return Task.FromResult(reply);
    }

    public override Task<FindStringsReply> FindStrings(FindStringsRequest request, ServerCallContext context)
    {
        var reply = new FindStringsReply { Success = true };
        reply.Strings.Add(new FoundStringInfo
        {
            Address = "00002000",
            Text = "config.ini",
            IsUnicode = false,
            XrefFrom = { "00001500" },
        });
        return Task.FromResult(reply);
    }
}

/// <summary>Echoes the comment type the client sent (as the error), to verify the
/// <see cref="CommentType"/> enum &rarr; wire-string mapping in SetComment.</summary>
internal sealed class CapturingFake : ProtoSvc.GhidraSharpServiceBase
{
    public override Task<AckReply> SetComment(SetCommentRequest request, ServerCallContext context) =>
        Task.FromResult(new AckReply { Success = false, Error = request.Type });
}

/// <summary>Returns a ListFunctions reply well over the default 4 MB gRPC receive cap.</summary>
internal sealed class BigListFake : ProtoSvc.GhidraSharpServiceBase
{
    public const int Count = 5000;

    public override Task<ListFunctionsReply> ListFunctions(ListFunctionsRequest request, ServerCallContext context)
    {
        var reply = new ListFunctionsReply { Success = true };
        var name = new string('x', 1000); // 5000 * ~1 KB ≈ 5 MB, exceeds the 4 MB default
        for (var i = 0; i < Count; i++)
        {
            reply.Functions.Add(new FunctionInfo { Name = name, EntryAddress = i.ToString("x8", CultureInfo.InvariantCulture) });
        }
        return Task.FromResult(reply);
    }
}

/// <summary>Overrides nothing — every RPC returns UNIMPLEMENTED, like a server older than
/// the client. Exercises the version-skew error path.</summary>
internal sealed class BareFake : ProtoSvc.GhidraSharpServiceBase
{
}

/// <summary>A fake that fails every RPC with the same error, to exercise the client's
/// error mapping across the whole surface.</summary>
internal sealed class FailingFake : ProtoSvc.GhidraSharpServiceBase
{
    private const string Boom = "boom";

    public override Task<OpenProgramReply> OpenProgram(OpenProgramRequest request, ServerCallContext context) =>
        Task.FromResult(new OpenProgramReply { Success = false, Error = Boom });

    public override Task<OpenProgramReply> CreateProject(CreateProjectRequest request, ServerCallContext context) =>
        Task.FromResult(new OpenProgramReply { Success = false, Error = Boom });

    public override Task<SaveProgramReply> SaveProgram(SaveProgramRequest request, ServerCallContext context) =>
        Task.FromResult(new SaveProgramReply { Success = false, Error = Boom });

    public override Task<AckReply> CloseProgram(CloseProgramRequest request, ServerCallContext context) =>
        Task.FromResult(new AckReply { Success = false, Error = Boom });

    public override Task<DecompileReply> DecompileFunction(DecompileRequest request, ServerCallContext context) =>
        Task.FromResult(new DecompileReply { Success = false, Error = Boom });

    public override async Task DecompileFunctions(DecompileFunctionsRequest request,
        IServerStreamWriter<DecompileReply> responseStream, ServerCallContext context) =>
        await responseStream.WriteAsync(new DecompileReply { Success = false, Error = Boom });

    public override Task<ListFunctionsReply> ListFunctions(ListFunctionsRequest request, ServerCallContext context) =>
        Task.FromResult(new ListFunctionsReply { Success = false, Error = Boom });

    public override Task<FunctionDetailReply> GetFunction(FunctionRequest request, ServerCallContext context) =>
        Task.FromResult(new FunctionDetailReply { Success = false, Error = Boom });

    public override Task<ReferencesReply> GetReferencesTo(ReferencesRequest request, ServerCallContext context) =>
        Task.FromResult(new ReferencesReply { Success = false, Error = Boom });

    public override Task<ReferencesReply> GetReferencesFrom(ReferencesRequest request, ServerCallContext context) =>
        Task.FromResult(new ReferencesReply { Success = false, Error = Boom });

    public override Task<ReferencesReply> GetFunctionReferences(ReferencesRequest request, ServerCallContext context) =>
        Task.FromResult(new ReferencesReply { Success = false, Error = Boom });

    public override Task<ListSymbolsReply> ListSymbols(ListSymbolsRequest request, ServerCallContext context) =>
        Task.FromResult(new ListSymbolsReply { Success = false, Error = Boom });

    public override Task<ListSymbolsReply> GetSymbolsAt(SymbolsAtRequest request, ServerCallContext context) =>
        Task.FromResult(new ListSymbolsReply { Success = false, Error = Boom });

    public override Task<RenameSymbolReply> RenameSymbol(RenameSymbolRequest request, ServerCallContext context) =>
        Task.FromResult(new RenameSymbolReply { Success = false, Error = Boom });

    public override Task<FindStringsReply> FindStrings(FindStringsRequest request, ServerCallContext context) =>
        Task.FromResult(new FindStringsReply { Success = false, Error = Boom });

    public override Task<ReadBytesReply> ReadBytes(ReadBytesRequest request, ServerCallContext context) =>
        Task.FromResult(new ReadBytesReply { Success = false, Error = Boom });

    public override Task<InstructionsReply> GetInstructions(InstructionsRequest request, ServerCallContext context) =>
        Task.FromResult(new InstructionsReply { Success = false, Error = Boom });

    public override Task<InstructionDetailReply> GetInstructionDetail(InstructionDetailRequest request, ServerCallContext context) =>
        Task.FromResult(new InstructionDetailReply { Success = false, Error = Boom });

    public override Task<DataReply> GetDataAt(DataAtRequest request, ServerCallContext context) =>
        Task.FromResult(new DataReply { Success = false, Error = Boom });

    public override Task<DataReply> ApplyDataType(ApplyDataTypeRequest request, ServerCallContext context) =>
        Task.FromResult(new DataReply { Success = false, Error = Boom });

    public override Task<DataTypesReply> ListDataTypes(DataTypesRequest request, ServerCallContext context) =>
        Task.FromResult(new DataTypesReply { Success = false, Error = Boom });

    public override Task<CommentsReply> GetComments(CommentsRequest request, ServerCallContext context) =>
        Task.FromResult(new CommentsReply { Success = false, Error = Boom });

    public override Task<AckReply> SetComment(SetCommentRequest request, ServerCallContext context) =>
        Task.FromResult(new AckReply { Success = false, Error = Boom });

    public override Task<BookmarksReply> GetBookmarks(BookmarksRequest request, ServerCallContext context) =>
        Task.FromResult(new BookmarksReply { Success = false, Error = Boom });

    public override Task<AckReply> SetBookmark(SetBookmarkRequest request, ServerCallContext context) =>
        Task.FromResult(new AckReply { Success = false, Error = Boom });

    public override Task<ListMemoryBlocksReply> ListMemoryBlocks(ListMemoryBlocksRequest request, ServerCallContext context) =>
        Task.FromResult(new ListMemoryBlocksReply { Success = false, Error = Boom });

    public override Task<ListLanguagesReply> ListLanguages(ListLanguagesRequest request, ServerCallContext context) =>
        Task.FromResult(new ListLanguagesReply { Success = false, Error = Boom });

    public override Task<RunScriptReply> RunScript(RunScriptRequest request, ServerCallContext context) =>
        Task.FromResult(new RunScriptReply { Success = false, Error = Boom });
}
