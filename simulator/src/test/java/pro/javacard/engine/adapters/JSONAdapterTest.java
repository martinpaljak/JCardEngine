package pro.javacard.engine.adapters;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.licel.jcardsim.base.Simulator;
import com.licel.jcardsim.samples.DualInterfaceApplet;
import com.licel.jcardsim.utils.AIDUtil;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.time.Duration;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

// Verifies the JSON adapter contract: one TCP connection = one request/response pair,
// session state persists across connections.
public class JSONAdapterTest {
    static final int TEST_PORT = 19025;
    static final ObjectMapper mapper = new ObjectMapper();
    static final String AID_HEX = "D0000CAFE00001";

    ExecutorService exec;
    JSONAdapter adapter;

    @BeforeEach
    void setUp() throws Exception {
        var sim = new Simulator();
        sim.installApplet(AIDUtil.create(AID_HEX), DualInterfaceApplet.class);

        adapter = new JSONAdapter(p -> sim.connectFor(Duration.ofSeconds(2), p, true));
        adapter.withPort(TEST_PORT);
        exec = Executors.newSingleThreadExecutor();
        exec.submit(adapter);
        Thread.sleep(200); // let server bind
    }

    @AfterEach
    void tearDown() throws Exception {
        adapter.shutdown();
        exec.shutdownNow();
        exec.awaitTermination(2, TimeUnit.SECONDS);
    }

    JsonNode send(ObjectNode json) throws IOException {
        try (var ch = SocketChannel.open()) {
            ch.connect(new InetSocketAddress("127.0.0.1", TEST_PORT));
            ch.write(ByteBuffer.wrap(mapper.writeValueAsBytes(json)));
            ch.shutdownOutput();
            var buf = ByteBuffer.allocate(4096);
            ch.read(buf);
            buf.flip();
            var bytes = new byte[buf.remaining()];
            buf.get(bytes);
            return mapper.readTree(bytes);
        }
    }

    @Test
    void testSessionAcrossConnections() throws Exception {
        // Open - each send() is a separate TCP connection
        var opened = send(mapper.createObjectNode().put("command", "open").put("protocol", "T=1"));
        assertEquals("open", opened.get("command").asText());
        assertNotNull(opened.get("response")); // ATR

        // SELECT on a new TCP connection - proves session persists
        var select = send(mapper.createObjectNode().put("command", "apdu").put("data", "00A4040007D0000CAFE00001"));
        assertEquals("apdu", select.get("command").asText());
        assertTrue(select.get("response").asText().endsWith("9000"));

        // Garbage APDU - error SW flows back through the adapter
        var garbage = send(mapper.createObjectNode().put("command", "apdu").put("data", "FF000000"));
        assertNotNull(garbage.get("response"));
        assertFalse(garbage.get("response").asText().endsWith("9000"));

        // Close
        var closed = send(mapper.createObjectNode().put("command", "close"));
        assertEquals("close", closed.get("command").asText());
    }
}
