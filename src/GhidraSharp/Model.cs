namespace Const24.GhidraSharp;

// Public, documented result types for the GhidraSharp API. The gRPC wire types
// (Const24.GhidraSharp.Protocol.*) are an implementation detail and never leak
// out of GhidraClient; these hand-written records are what callers see, so they
// get clean IntelliSense and names that read well both to a Ghidra user and to
// a .NET developer who has never opened Ghidra.

/// <summary>Information about the Ghidra instance the server is running.</summary>
public sealed record ServerInfo
{
    /// <summary>The Ghidra release version, e.g. <c>"12.1"</c> (Ghidra's <c>Application.getApplicationVersion()</c>).</summary>
    public required string GhidraVersion { get; init; }
}

/// <summary>
/// Summary of an open <em>program</em> — Ghidra's term for a single loaded binary
/// (here, one firmware image) together with its disassembly and analysis.
/// </summary>
public sealed record ProgramInfo
{
    /// <summary>The program's name in Ghidra (typically the imported file name).</summary>
    public required string Name { get; init; }

    /// <summary>
    /// Ghidra language/compiler-spec id describing the processor, e.g.
    /// <c>"SuperH:BE:32:SH-2A"</c> (processor:endianness:size:variant).
    /// </summary>
    public required string LanguageId { get; init; }

    /// <summary>The program's image base — the address the binary is loaded at.</summary>
    public required ulong ImageBase { get; init; }

    /// <summary>Number of functions Ghidra has defined in the program.</summary>
    public required int FunctionCount { get; init; }
}

/// <summary>
/// A function in the current program, carrying enough detail to query a whole
/// list client-side with LINQ without a round trip per function.
/// </summary>
public sealed record GhidraFunction
{
    /// <summary>The function's name (e.g. an auto-generated <c>FUN_00002730</c> or a user-applied name).</summary>
    public required string Name { get; init; }

    /// <summary>The entry-point address as hex (Ghidra's <c>Function.getEntryPoint()</c>), e.g. <c>"00002730"</c>.</summary>
    public required string EntryPoint { get; init; }

    /// <summary>Size of the function body in addresses/bytes (Ghidra's <c>getBody().getNumAddresses()</c>).</summary>
    public required ulong Size { get; init; }

    /// <summary>Number of parameters Ghidra has inferred for the function.</summary>
    public required int ParameterCount { get; init; }

    /// <summary>Whether this is a thunk (a trampoline that forwards to another function).</summary>
    public required bool IsThunk { get; init; }

    /// <summary>
    /// Names of the functions this one calls (its callees). Populated only when
    /// <see cref="GhidraClient.ListFunctionsAsync"/> is asked to include calls;
    /// otherwise empty.
    /// </summary>
    public required IReadOnlyList<string> Calls { get; init; }
}

/// <summary>
/// The result of decompiling one function to C. Decompilation can fail for an
/// individual function (e.g. a timeout) without being an error for the call, so
/// the outcome is carried in <see cref="IsSuccess"/> rather than thrown.
/// </summary>
public sealed record Decompilation
{
    /// <summary>Whether Ghidra's decompiler completed for this function.</summary>
    public required bool IsSuccess { get; init; }

    /// <summary>The entry-point address of the decompiled function, as hex.</summary>
    public required string EntryPoint { get; init; }

    /// <summary>The reconstructed C signature, e.g. <c>"undefined2 FUN_00002730(void)"</c>.</summary>
    public required string Signature { get; init; }

    /// <summary>The decompiled C source (Ghidra's <c>DecompiledFunction.getC()</c>). Empty when <see cref="IsSuccess"/> is false.</summary>
    public required string CCode { get; init; }

    /// <summary>The decompiler's error message when <see cref="IsSuccess"/> is false; otherwise empty.</summary>
    public required string Error { get; init; }
}

/// <summary>
/// A cross-reference ("xref") — a directed link from one address to another that
/// Ghidra recorded during analysis, such as a call, a jump, or a data access.
/// </summary>
public sealed record GhidraReference
{
    /// <summary>The address the reference originates from, as hex.</summary>
    public required string FromAddress { get; init; }

    /// <summary>The address the reference points to, as hex.</summary>
    public required string ToAddress { get; init; }

    /// <summary>
    /// Ghidra's reference-type name (the <c>RefType</c>), e.g.
    /// <c>"UNCONDITIONAL_CALL"</c>, <c>"CONDITIONAL_JUMP"</c>, <c>"READ"</c>, <c>"DATA"</c>.
    /// </summary>
    public required string ReferenceType { get; init; }

    /// <summary>Whether this reference is a call (any flavour of call <c>RefType</c>).</summary>
    public required bool IsCall { get; init; }

    /// <summary>Whether this reference is a jump/branch.</summary>
    public required bool IsJump { get; init; }

    /// <summary>Whether this reference is a data access (read/write/pointer) rather than control flow.</summary>
    public required bool IsData { get; init; }

    /// <summary>
    /// Index of the instruction operand the reference is attached to, or <c>-1</c>
    /// for a mnemonic-level reference (Ghidra's <c>CodeUnit.MNEMONIC</c>).
    /// </summary>
    public required int OperandIndex { get; init; }

    /// <summary>Whether this is the primary reference from that source address/operand.</summary>
    public required bool IsPrimary { get; init; }
}

/// <summary>
/// A symbol — a name bound to an address in the program (a function name, a
/// label, a parameter, a global variable, …). Renaming one is how a finding gets
/// recorded back onto the program.
/// </summary>
public sealed record GhidraSymbol
{
    /// <summary>The symbol's name.</summary>
    public required string Name { get; init; }

    /// <summary>The address the symbol is bound to, as hex.</summary>
    public required string Address { get; init; }

    /// <summary>Ghidra's symbol type, e.g. <c>"Function"</c>, <c>"Label"</c>, <c>"Parameter"</c>, <c>"Global"</c>.</summary>
    public required string SymbolType { get; init; }

    /// <summary>
    /// Where the name came from (Ghidra's <c>SourceType</c>): <c>"USER_DEFINED"</c>,
    /// <c>"IMPORTED"</c>, <c>"ANALYSIS"</c>, or <c>"DEFAULT"</c> (auto-generated).
    /// </summary>
    public required string Source { get; init; }

    /// <summary>Whether this is the primary symbol at its address (the one shown by default).</summary>
    public required bool IsPrimary { get; init; }

    /// <summary>Whether the symbol lives in the global namespace (vs. a function/local namespace).</summary>
    public required bool IsGlobal { get; init; }
}

/// <summary>A single disassembled machine instruction from the program listing.</summary>
public sealed record Instruction
{
    /// <summary>The instruction's address, as hex.</summary>
    public required string Address { get; init; }

    /// <summary>The mnemonic, e.g. <c>"mov.l"</c> (Ghidra's <c>getMnemonicString()</c>).</summary>
    public required string Mnemonic { get; init; }

    /// <summary>The full instruction text including operands, e.g. <c>"mov.l @r4,r1"</c>.</summary>
    public required string Representation { get; init; }

    /// <summary>The instruction's encoded bytes.</summary>
    public required byte[] Bytes { get; init; }

    /// <summary>The instruction length in bytes.</summary>
    public required int Length { get; init; }
}

/// <summary>A function parameter or local variable.</summary>
public sealed record GhidraVariable
{
    /// <summary>The variable's name.</summary>
    public required string Name { get; init; }

    /// <summary>Its data type's display name, e.g. <c>"int"</c>, <c>"undefined4 *"</c>.</summary>
    public required string DataType { get; init; }

    /// <summary>Ghidra's storage description, e.g. <c>"r4:4"</c> (register) or <c>"Stack[-0x8]:4"</c>.</summary>
    public required string Storage { get; init; }
}

/// <summary>
/// Full detail for one function — the typed view beyond <see cref="GhidraFunction"/>:
/// reconstructed prototype, parameters and locals with types, and callers.
/// </summary>
public sealed record FunctionDetail
{
    /// <summary>The function's name.</summary>
    public required string Name { get; init; }

    /// <summary>The entry-point address, as hex.</summary>
    public required string EntryPoint { get; init; }

    /// <summary>The reconstructed prototype string (with calling convention).</summary>
    public required string Signature { get; init; }

    /// <summary>The return type's display name.</summary>
    public required string ReturnType { get; init; }

    /// <summary>The calling convention name (e.g. <c>"__stdcall"</c>, <c>"default"</c>).</summary>
    public required string CallingConvention { get; init; }

    /// <summary>Whether the function is marked no-return.</summary>
    public required bool NoReturn { get; init; }

    /// <summary>Whether the function takes variadic arguments.</summary>
    public required bool VarArgs { get; init; }

    /// <summary>Whether the function is marked inline.</summary>
    public required bool Inline { get; init; }

    /// <summary>Size of the function body in addresses/bytes.</summary>
    public required ulong Size { get; init; }

    /// <summary>The parameters, in order.</summary>
    public required IReadOnlyList<GhidraVariable> Parameters { get; init; }

    /// <summary>The local variables.</summary>
    public required IReadOnlyList<GhidraVariable> Locals { get; init; }

    /// <summary>Names of the functions that call this one (populated when requested).</summary>
    public required IReadOnlyList<string> Callers { get; init; }
}

/// <summary>A defined data item in the program (a value Ghidra has typed at an address).</summary>
public sealed record DataItem
{
    /// <summary>The data's address, as hex.</summary>
    public required string Address { get; init; }

    /// <summary>The data type's display name, e.g. <c>"float"</c>, <c>"char[16]"</c>.</summary>
    public required string DataType { get; init; }

    /// <summary>Length in bytes.</summary>
    public required int Length { get; init; }

    /// <summary>Ghidra's default value representation (e.g. <c>"1.5"</c>, <c>"0x1234"</c>, a string literal).</summary>
    public required string Value { get; init; }

    /// <summary>Whether the data is a pointer.</summary>
    public required bool IsPointer { get; init; }

    /// <summary>When <see cref="IsPointer"/>, the address it points to (hex); otherwise empty.</summary>
    public required string PointerTarget { get; init; }

    /// <summary>False when there is no defined data at the requested address.</summary>
    public required bool Defined { get; init; }
}

/// <summary>A data type known to the program (a struct, enum, typedef, pointer, built-in, …).</summary>
public sealed record GhidraDataType
{
    /// <summary>The type's name.</summary>
    public required string Name { get; init; }

    /// <summary>Its display name (how it renders in listings).</summary>
    public required string DisplayName { get; init; }

    /// <summary>Its category path, e.g. <c>"/MyStructs/Header"</c>.</summary>
    public required string Path { get; init; }

    /// <summary>Kind: <c>Structure</c>, <c>Enum</c>, <c>TypeDef</c>, <c>Union</c>, <c>Pointer</c>, <c>Array</c>, <c>BuiltIn</c>, or <c>Other</c>.</summary>
    public required string Kind { get; init; }

    /// <summary>Length in bytes, or <c>-1</c> for a dynamically-sized type.</summary>
    public required int Length { get; init; }
}

/// <summary>The captured output of a <see cref="GhidraClient.RunScriptAsync"/> call.</summary>
public sealed record ScriptOutput
{
    /// <summary>Everything the script wrote to standard out.</summary>
    public required string Stdout { get; init; }

    /// <summary>Everything the script wrote to standard error.</summary>
    public required string Stderr { get; init; }
}

/// <summary>The kind of comment, matching Ghidra's comment types.</summary>
public enum CommentType
{
    /// <summary>End-of-line comment.</summary>
    Eol,

    /// <summary>Comment before the code unit.</summary>
    Pre,

    /// <summary>Comment after the code unit.</summary>
    Post,

    /// <summary>Plate (banner) comment above a function/block.</summary>
    Plate,

    /// <summary>Repeatable comment (shown at every reference site).</summary>
    Repeatable,
}

/// <summary>The comments of every type at an address.</summary>
public sealed record Comments
{
    /// <summary>End-of-line comment (empty if none).</summary>
    public required string Eol { get; init; }

    /// <summary>Pre comment.</summary>
    public required string Pre { get; init; }

    /// <summary>Post comment.</summary>
    public required string Post { get; init; }

    /// <summary>Plate comment.</summary>
    public required string Plate { get; init; }

    /// <summary>Repeatable comment.</summary>
    public required string Repeatable { get; init; }
}

/// <summary>A bookmark (a marked, categorized note Ghidra keeps at an address).</summary>
public sealed record GhidraBookmark
{
    /// <summary>The bookmarked address, as hex.</summary>
    public required string Address { get; init; }

    /// <summary>The bookmark type, e.g. <c>"Note"</c>, <c>"Analysis"</c>, <c>"Error"</c>.</summary>
    public required string Type { get; init; }

    /// <summary>Its category.</summary>
    public required string Category { get; init; }

    /// <summary>Its comment text.</summary>
    public required string Comment { get; init; }
}

/// <summary>One operand of an instruction.</summary>
public sealed record Operand
{
    /// <summary>Operand index within the instruction.</summary>
    public required int Index { get; init; }

    /// <summary>How the operand renders, e.g. <c>"@r4"</c>, <c>"0x10"</c>.</summary>
    public required string Representation { get; init; }

    /// <summary>Ghidra's <c>OperandType</c> flags as text (e.g. <c>"register"</c>, <c>"scalar | address"</c>).</summary>
    public required string Type { get; init; }

    /// <summary>Register name when the operand is a register; otherwise empty.</summary>
    public required string Register { get; init; }

    /// <summary>Whether the operand carries a scalar constant.</summary>
    public required bool HasScalar { get; init; }

    /// <summary>The scalar value, when <see cref="HasScalar"/>.</summary>
    public required long Scalar { get; init; }
}

/// <summary>One raw PCode operation — Ghidra's low-level IR for an instruction.</summary>
public sealed record PcodeOp
{
    /// <summary>The op's mnemonic, e.g. <c>"COPY"</c>, <c>"INT_ADD"</c>, <c>"LOAD"</c>.</summary>
    public required string Mnemonic { get; init; }

    /// <summary>The output varnode as text, or empty when the op has no output.</summary>
    public required string Output { get; init; }

    /// <summary>The input varnodes as text.</summary>
    public required IReadOnlyList<string> Inputs { get; init; }
}

/// <summary>
/// One instruction in full: its operands (structured) and its raw PCode. The
/// deeper decompiler IR (high PCode / HighFunction) is intentionally not bridged —
/// reach it with <see cref="GhidraClient.RunScriptAsync"/>.
/// </summary>
public sealed record InstructionDetail
{
    /// <summary>The instruction's address, as hex.</summary>
    public required string Address { get; init; }

    /// <summary>The mnemonic.</summary>
    public required string Mnemonic { get; init; }

    /// <summary>The full instruction text.</summary>
    public required string Representation { get; init; }

    /// <summary>The encoded bytes.</summary>
    public required byte[] Bytes { get; init; }

    /// <summary>Length in bytes.</summary>
    public required int Length { get; init; }

    /// <summary>The structured operands.</summary>
    public required IReadOnlyList<Operand> Operands { get; init; }

    /// <summary>The raw PCode operations the instruction lifts to.</summary>
    public required IReadOnlyList<PcodeOp> Pcode { get; init; }
}

/// <summary>Error raised when the Ghidra server reports a failure for a request.</summary>
public sealed class GhidraException : Exception
{
    /// <summary>Create a <see cref="GhidraException"/> with the server-provided message.</summary>
    public GhidraException(string message) : base(message)
    {
    }
}
