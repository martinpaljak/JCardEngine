// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.faulty;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import org.testng.annotations.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

import static org.testng.Assert.*;

public class FaultyConfigTest {

    private static final Logger log = LoggerFactory.getLogger(FaultyConfigTest.class);

    @Test
    public void testParse() throws Exception {
        var objectMapper = new ObjectMapper(new YAMLFactory());
        var r = objectMapper.readValue(getClass().getResourceAsStream("faulty.yaml"), FaultyConfig.class);
        log.info("Read {} ", objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(r));

        assertEquals(r.step().size(), 2);
        assertEquals(r.apdu().size(), 2);
    }

    @Test
    public void testGetFaultsByStep() throws Exception {
        var objectMapper = new ObjectMapper(new YAMLFactory());
        var config = objectMapper.readValue(getClass().getResourceAsStream("faulty.yaml"), FaultyConfig.class);

        // Query step 1 with non-matching APDU
        var faults = config.getFaults(1, new byte[]{0x00, 0x00, 0x00, 0x00});
        assertEquals(faults.size(), 1);
        assertTrue(faults.containsKey("FooBar"));
        assertEquals(faults.get("FooBar").size(), 3);
    }

    @Test
    public void testGetFaultsByApdu() throws Exception {
        var objectMapper = new ObjectMapper(new YAMLFactory());
        var config = objectMapper.readValue(getClass().getResourceAsStream("faulty.yaml"), FaultyConfig.class);

        // Query non-matching step with SELECT APDU
        var faults = config.getFaults(99, new byte[]{0x00, (byte) 0xA4, 0x04, 0x00});
        assertEquals(faults.size(), 1);
        assertTrue(faults.containsKey("SelectHandler"));
        assertEquals(faults.get("SelectHandler").get(56), "exception");
    }

    @Test
    public void testGetFaultsByApduWildcard() throws Exception {
        var objectMapper = new ObjectMapper(new YAMLFactory());
        var config = objectMapper.readValue(getClass().getResourceAsStream("faulty.yaml"), FaultyConfig.class);

        // Query with GET DATA APDU matching 80CAXXXX pattern
        var faults = config.getFaults(99,
                new byte[]{(byte) 0x80, (byte) 0xCA, (byte) 0x9F, 0x17 });
        assertEquals(faults.size(), 1);
        assertTrue(faults.containsKey("GetDataHandler"));
        assertEquals(faults.get("GetDataHandler").size(), 2);
    }

    @Test
    public void testGetFaultsMerged() throws Exception {
        var objectMapper = new ObjectMapper(new YAMLFactory());
        var config = objectMapper.readValue(getClass().getResourceAsStream("faulty.yaml"), FaultyConfig.class);

        // Query step 1 with SELECT APDU - should merge both
        var faults = config.getFaults(1, new byte[]{0x00, (byte) 0xA4, 0x04, 0x00});
        assertEquals(faults.size(), 2);
        assertTrue(faults.containsKey("FooBar"));
        assertTrue(faults.containsKey("SelectHandler"));
    }

    @Test
    public void testEmptyConfig() throws Exception {
        var objectMapper = new ObjectMapper(new YAMLFactory());
        var config = objectMapper.readValue("{}", FaultyConfig.class);

        var faults = config.getFaults(1, new byte[]{0x00, 0x00, 0x00, 0x00});
        assertTrue(faults.isEmpty());
    }
}
