package com.ot.sentinel.service;

import com.ot.sentinel.model.LogEntry;
import com.ot.sentinel.repository.LogEntryRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockMultipartFile;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the proprietary raw-text -> CSV normalisation layer.
 */
class RawLogNormalizerServiceTest {

    private LogParserService logParserService;
    private RawLogNormalizerService service;

    @BeforeEach
    void setUp() {
        LogEntryRepository repo = mock(LogEntryRepository.class);
        when(repo.saveAll(anyList())).thenAnswer(inv -> inv.getArgument(0));
        logParserService = new LogParserService(repo);
        service = new RawLogNormalizerService(logParserService);
    }

    private String normalize(String... lines) throws IOException {
        return service.normalizeToCsv(new BufferedReader(new StringReader(String.join("\n", lines))), "test.txt");
    }

    @Test
    void extractsAllFieldsIntoCanonicalCsv() throws IOException {
        String csv = normalize(
                "[2026-11-10 08:05:02] WARN Device=HMI-CONTROL-03 Source=192.168.1.50 Action=LOGIN Result=FAIL");

        assertThat(csv).startsWith("timestamp,sourceIp,command,status,deviceId\n");
        assertThat(csv).contains("2026-11-10 08:05:02,192.168.1.50,LOGIN,FAILURE,HMI-CONTROL-03");
    }

    @Test
    void normalizesVendorStatusVocabulary() throws IOException {
        String csv = normalize(
                "[2026-11-10 08:00:00] INFO Device=PLC-01 Source=10.0.0.1 Action=READ Result=OK",
                "[2026-11-10 08:00:01] INFO Device=PLC-01 Source=10.0.0.1 Action=READ Result=GRANTED",
                "[2026-11-10 08:00:02] ERROR Device=PLC-02 Source=10.0.0.2 Action=STOP Result=DENIED",
                "[2026-11-10 08:00:03] ERROR Device=PLC-02 Source=10.0.0.2 Action=STOP Result=ERROR",
                "[2026-11-10 08:00:04] WARN Device=PLC-02 Source=10.0.0.2 Action=WRITE Result=TIMEOUT");

        assertThat(csv).contains(",SUCCESS,PLC-01").doesNotContain("OK,");
        assertThat(csv).contains(",SUCCESS,PLC-01").doesNotContain("GRANTED,");
        assertThat(csv).contains(",FAILURE,PLC-02").doesNotContain("DENIED,");
        assertThat(csv).contains(",FAILURE,PLC-02").doesNotContain("ERROR,");
        assertThat(csv).contains(",FAILURE,PLC-02").doesNotContain("TIMEOUT,");
    }

    @Test
    void skipsUnrecognisedLinesWithoutFailing() throws IOException {
        String csv = normalize(
                "some random vendor banner",
                "",
                "[2026-11-10 08:00:00] INFO Device=PLC-01 Source=10.0.0.1 Action=READ Result=OK",
                "Device=broken truncated line");

        String[] rows = csv.split("\n");
        assertThat(rows).hasSize(2); // header + 1 accepted row
        assertThat(rows[1]).contains("2026-11-10 08:00:00,10.0.0.1,READ,SUCCESS,PLC-01");
    }

    @Test
    void toleratesExtraWhitespaceAndHostnames() throws IOException {
        String csv = normalize(
                "[ 2026-11-10 08:00:00 ]   INFO   Device=RTU-9   Source=plc-floor-1.local   Action=WRITE   Result=OK");

        assertThat(csv).contains("2026-11-10 08:00:00,plc-floor-1.local,WRITE,SUCCESS,RTU-9");
    }

    @Test
    void endToEndIngestRawFilePersistsNormalizedEntries() throws IOException {
        String raw = """
                [2026-11-10 08:05:02] WARN Device=HMI-CONTROL-03 Source=192.168.1.50 Action=LOGIN Result=FAIL
                [2026-11-10 08:05:30] INFO Device=PLC-01 Source=192.168.1.10 Action=READ Result=OK
                garbage line
                """;
        MockMultipartFile file = new MockMultipartFile("file", "raw_plc_logs.txt", "text/plain",
                raw.getBytes(StandardCharsets.UTF_8));

        List<LogEntry> saved = service.ingestRawLogs(file);

        assertThat(saved).hasSize(2);
        assertThat(saved.get(0).getStatus()).isEqualTo("FAILURE");
        assertThat(saved.get(0).getCommandType()).isEqualTo("LOGIN");
        assertThat(saved.get(0).getSourceIp()).isEqualTo("192.168.1.50");
        assertThat(saved.get(0).getDeviceId()).isEqualTo("HMI-CONTROL-03");
        assertThat(saved.get(0).getEventTime()).isEqualTo(java.time.LocalDateTime.of(2026, 11, 10, 8, 5, 2));
        assertThat(saved.get(1).getStatus()).isEqualTo("SUCCESS");
    }

    @Test
    void unknownStatusPassesThroughUpperCased() {
        assertThat(RawLogNormalizerService.normalizeStatus("busy")).isEqualTo("BUSY");
        assertThat(RawLogNormalizerService.normalizeStatus("fail")).isEqualTo("FAILURE");
        assertThat(RawLogNormalizerService.normalizeStatus("ok")).isEqualTo("SUCCESS");
    }
}
