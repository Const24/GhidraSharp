package io.github.const24.ghidrasharp.server;

import io.github.const24.ghidrasharp.proto.*;
import io.github.const24.ghidrasharp.server.service.GhidraSharpServiceImpl;
import io.grpc.ManagedChannel;
import io.grpc.Server;
import io.grpc.inprocess.InProcessChannelBuilder;
import io.grpc.inprocess.InProcessServerBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Exercises {@link GhidraSharpServiceImpl} over an in-process gRPC channel with a
 * {@link FakeEngine}, asserting the engine-result → proto mapping. No Ghidra.
 */
class GhidraSharpServiceImplTest {

    private Server server;
    private ManagedChannel channel;
    private GhidraSharpServiceGrpc.GhidraSharpServiceBlockingStub stub;

    @BeforeEach
    void start() throws Exception {
        String name = InProcessServerBuilder.generateName();
        server = InProcessServerBuilder.forName(name).directExecutor()
                .addService(new GhidraSharpServiceImpl(new FakeEngine()))
                .build().start();
        channel = InProcessChannelBuilder.forName(name).directExecutor().build();
        stub = GhidraSharpServiceGrpc.newBlockingStub(channel);
    }

    @AfterEach
    void stop() {
        channel.shutdownNow();
        server.shutdownNow();
    }

    @Test
    void ping_reports_the_engine_version() {
        PingReply r = stub.ping(PingRequest.newBuilder().setMessage("hi").build());
        assertEquals("test-version", r.getGhidraVersion());
    }

    @Test
    void listFunctions_maps_fields_and_calls() {
        ListFunctionsReply r = stub.listFunctions(ListFunctionsRequest.newBuilder().setIncludeCalls(true).build());
        assertTrue(r.getSuccess());
        assertEquals(1, r.getFunctionsCount());
        FunctionInfo fn = r.getFunctions(0);
        assertEquals("fn1", fn.getName());
        assertEquals(20L, fn.getSize());
        assertEquals(2, fn.getParameterCount());
        assertEquals(List.of("callee_a", "callee_b"), fn.getCallsList());
    }

    @Test
    void getReferencesTo_maps_xref() {
        ReferencesReply r = stub.getReferencesTo(ReferencesRequest.newBuilder().setAddress("00001000").build());
        Reference ref = r.getReferences(0);
        assertEquals("00001100", ref.getFromAddress());
        assertEquals("00001000", ref.getToAddress());
        assertEquals("UNCONDITIONAL_CALL", ref.getReferenceType());
        assertTrue(ref.getIsCall());
    }

    @Test
    void getFunctionReferences_maps_xrefs() {
        ReferencesReply r = stub.getFunctionReferences(ReferencesRequest.newBuilder().setAddress("00001000").build());
        assertTrue(r.getSuccess());
        Reference ref = r.getReferences(0);
        assertEquals("00001100", ref.getFromAddress());
        assertEquals("00001000", ref.getToAddress());
        assertTrue(ref.getIsCall());
    }

    @Test
    void decompileFunction_maps_result() {
        DecompileReply r = stub.decompileFunction(DecompileRequest.newBuilder().setAddress("0x1000").build());
        assertTrue(r.getSuccess());
        assertEquals("void fn(void)", r.getSignature());
        assertEquals("00001000", r.getEntryAddress());
    }

    @Test
    void decompileFunctions_streams_all() {
        Iterator<DecompileReply> it = stub.decompileFunctions(
                DecompileFunctionsRequest.newBuilder().setAll(true).build());
        List<DecompileReply> all = new ArrayList<>();
        it.forEachRemaining(all::add);
        assertEquals(2, all.size());
        assertEquals("00001000", all.get(0).getEntryAddress());
        assertEquals("00002000", all.get(1).getEntryAddress());
    }

    @Test
    void getDataAt_maps_data_item() {
        DataReply r = stub.getDataAt(DataAtRequest.newBuilder().setAddress("0x3000").build());
        assertTrue(r.getData().getDefined());
        assertEquals("float", r.getData().getDataType());
        assertEquals(4, r.getData().getLength());
        assertEquals("1.5", r.getData().getValue());
    }

    @Test
    void getFunction_maps_detail() {
        FunctionDetailReply r = stub.getFunction(FunctionRequest.newBuilder().setAddress("0x1000").build());
        FunctionDetail f = r.getFunction();
        assertEquals("int fn1(int p)", f.getSignature());
        assertEquals("__stdcall", f.getCallingConvention());
        assertEquals("p", f.getParameters(0).getName());
        assertEquals("r4:4", f.getParameters(0).getStorage());
        assertEquals("x", f.getLocalVariables(0).getName());
        assertEquals("caller_a", f.getCallers(0));
    }

    @Test
    void getInstructionDetail_maps_operands_and_pcode() {
        InstructionDetailReply r = stub.getInstructionDetail(
                InstructionDetailRequest.newBuilder().setAddress("0x1000").build());
        InstructionDetail d = r.getInstruction();
        assertArrayEquals(new byte[] {(byte) 0xAB, (byte) 0xCD}, d.getRawBytes().toByteArray());
        assertEquals(2, d.getOperandsCount());
        assertTrue(d.getOperands(1).getHasScalar());
        assertEquals(16L, d.getOperands(1).getScalar());
        assertEquals("COPY", d.getPcode(0).getMnemonic());
        assertEquals(1, d.getPcode(0).getInputsCount());
    }

    @Test
    void readBytes_maps_bytes() {
        ReadBytesReply r = stub.readBytes(ReadBytesRequest.newBuilder().setAddress("0x1000").setLength(2).build());
        assertArrayEquals(new byte[] {(byte) 0xDE, (byte) 0xAD}, r.getData().toByteArray());
    }

    @Test
    void setComment_passes_the_type_through() {
        AckReply r = stub.setComment(SetCommentRequest.newBuilder()
                .setAddress("0x1000").setType("EOL").setComment("x").build());
        assertTrue(r.getSuccess());
        assertEquals("EOL", r.getError()); // FakeEngine echoes the received type
    }

    @Test
    void saveProgram_succeeds() {
        SaveProgramReply r = stub.saveProgram(SaveProgramRequest.newBuilder().build());
        assertTrue(r.getSuccess());
    }

    @Test
    void closeProgram_succeeds() {
        AckReply r = stub.closeProgram(CloseProgramRequest.newBuilder().build());
        assertTrue(r.getSuccess());
    }

    @Test
    void listLanguages_maps_descriptors() {
        ListLanguagesReply r = stub.listLanguages(ListLanguagesRequest.newBuilder().build());
        assertTrue(r.getSuccess());
        assertEquals(1, r.getLanguagesCount());
        LanguageDescriptor l = r.getLanguages(0);
        assertEquals("SuperH:BE:32:SH-2A", l.getId());
        assertEquals("SuperH", l.getProcessor());
        assertEquals(32, l.getSize());
    }

    @Test
    void listMemoryBlocks_maps_block_range_and_permissions() {
        ListMemoryBlocksReply r = stub.listMemoryBlocks(ListMemoryBlocksRequest.newBuilder().build());
        assertTrue(r.getSuccess());
        assertEquals(1, r.getBlocksCount());
        MemoryBlockInfo b = r.getBlocks(0);
        assertEquals(".text", b.getName());
        assertEquals("00001000", b.getStart());
        assertEquals("00001fff", b.getEnd());
        assertEquals(4096L, b.getSize());
        assertTrue(b.getInitialized());
        assertTrue(b.getRead());
        assertFalse(b.getWrite());
        assertTrue(b.getExecute());
    }

    @Test
    void findStrings_maps_text_and_xrefs() {
        FindStringsReply r = stub.findStrings(FindStringsRequest.newBuilder().setSubstring("config").build());
        assertTrue(r.getSuccess());
        assertEquals(1, r.getStringsCount());
        FoundStringInfo s = r.getStrings(0);
        assertEquals("00002000", s.getAddress());
        assertEquals("config.ini", s.getText());
        assertFalse(s.getIsUnicode());
        assertEquals(1, s.getXrefFromCount());
        assertEquals("00001500", s.getXrefFrom(0));
    }
}
