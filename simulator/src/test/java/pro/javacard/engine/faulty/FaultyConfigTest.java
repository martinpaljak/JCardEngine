package pro.javacard.engine.faulty;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class FaultyConfigTest {

    private static final Logger log = LoggerFactory.getLogger(FaultyConfigTest.class);

    @Test
    public void testParse() throws Exception {
        ObjectMapper objectMapper = new ObjectMapper(new YAMLFactory());
        var r = objectMapper.readValue(getClass().getResourceAsStream("faulty.yaml"), FaultConfig.class);
        log.info("Read {} ", objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(r));

        Assertions.assertEquals(2, r.interactions().size());
    }
}
