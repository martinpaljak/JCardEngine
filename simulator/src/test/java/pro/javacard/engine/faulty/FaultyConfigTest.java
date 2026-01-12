package pro.javacard.engine.faulty;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

public class FaultyConfigTest {

    private static final Logger log = LoggerFactory.getLogger(FaultyConfigTest.class);

    @Test
    public void testParse() throws Exception {
        var objectMapper = new ObjectMapper(new YAMLFactory());
        var r = objectMapper.readValue(getClass().getResourceAsStream("faulty.yaml"), FaultyConfig.class);
        log.info("Read {} ", objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(r));

        Assertions.assertEquals(2, r.step().size());
        Assertions.assertEquals(2, r.apdu().size());
    }

    @Test
    public void testGetFaultsByStep() throws Exception {
        var objectMapper = new ObjectMapper(new YAMLFactory());
        var config = objectMapper.readValue(getClass().getResourceAsStream("faulty.yaml"), FaultyConfig.class);

        // Query step 1 with non-matching APDU
        var faults = config.getFaults(1, new byte[]{0x00, 0x00, 0x00, 0x00});
        Assertions.assertEquals(1, faults.size());
        Assertions.assertTrue(faults.containsKey("FooBar"));
        Assertions.assertEquals(3, faults.get("FooBar").size());
    }

    @Test
    public void testGetFaultsByApdu() throws Exception {
        var objectMapper = new ObjectMapper(new YAMLFactory());
        var config = objectMapper.readValue(getClass().getResourceAsStream("faulty.yaml"), FaultyConfig.class);

        // Query non-matching step with SELECT APDU
        var faults = config.getFaults(99, new byte[]{0x00, (byte) 0xA4, 0x04, 0x00});
        Assertions.assertEquals(1, faults.size());
        Assertions.assertTrue(faults.containsKey("SelectHandler"));
        Assertions.assertEquals("exception", faults.get("SelectHandler").get(56));
    }

    @Test
    public void testGetFaultsByApduWildcard() throws Exception {
        var objectMapper = new ObjectMapper(new YAMLFactory());
        var config = objectMapper.readValue(getClass().getResourceAsStream("faulty.yaml"), FaultyConfig.class);

        // Query with GET DATA APDU matching 80CAXXXX pattern
        var faults = config.getFaults(99,
                new byte[]{(byte) 0x80, (byte) 0xCA, (byte) 0x9F, 0x17 });
        Assertions.assertEquals(1, faults.size());
        Assertions.assertTrue(faults.containsKey("GetDataHandler"));
        Assertions.assertEquals(2, faults.get("GetDataHandler").size());
    }

    @Test
    public void testGetFaultsMerged() throws Exception {
        var objectMapper = new ObjectMapper(new YAMLFactory());
        var config = objectMapper.readValue(getClass().getResourceAsStream("faulty.yaml"), FaultyConfig.class);

        // Query step 1 with SELECT APDU - should merge both
        var faults = config.getFaults(1, new byte[]{0x00, (byte) 0xA4, 0x04, 0x00});
        Assertions.assertEquals(2, faults.size());
        Assertions.assertTrue(faults.containsKey("FooBar"));
        Assertions.assertTrue(faults.containsKey("SelectHandler"));
    }

    @Test
    public void testEmptyConfig() throws Exception {
        var objectMapper = new ObjectMapper(new YAMLFactory());
        var config = objectMapper.readValue("{}", FaultyConfig.class);

        var faults = config.getFaults(1, new byte[]{0x00, 0x00, 0x00, 0x00});
        Assertions.assertTrue(faults.isEmpty());
    }
}
