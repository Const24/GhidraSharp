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

/// <summary>Error raised when the Ghidra server reports a failure for a request.</summary>
public sealed class GhidraException : Exception
{
    /// <summary>Create a <see cref="GhidraException"/> with the server-provided message.</summary>
    public GhidraException(string message) : base(message)
    {
    }
}
