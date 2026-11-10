package com.ot.sentinel.service;

import com.ot.sentinel.model.LogEntry;
import com.ot.sentinel.repository.LogEntryRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockMultipartFile;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the CSV parsing engine.
 */
class LogParserServiceTest {

    private LogEntryRepository repository;
    private LogParserService service;

    @BeforeEach
    void setUp() {
        repository = mock(LogEntryRepository.class);
        service = new LogParserService(repository);
        when(repository.saveAll(anyList())).thenAnswer(inv -> inv.getArgument(0));
    }

    private MockMultipartFile csv(String content) {
        return new MockMultipartFile("file", "plc_logs.csv", "text/csv",
                content.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void parsesValidRowsAndSkipsHeader() throws IOException {
        String content = """
                timestamp,sourceIp,command,status,deviceId
                2026-11-10 08:00:00,192.168.1.10,READ,SUCCESS,PLC-01
                2026-11-10 08:00:05,192.168.1.20,LOGIN,FAILURE,PLC-02
                not,a,valid,row
                """;

        List<LogEntry> saved = service.parseAndSaveLogs(csv(content));

        assertThat(saved).hasSize(2);
        assertThat(saved.get(0).getSourceIp()).isEqualTo("192.168.1.10");
        assertThat(saved.get(0).getCommandType()).isEqualTo("READ");
        assertThat(saved.get(0).getStatus()).isEqualTo("SUCCESS");
        assertThat(saved.get(0).getTimestamp())
                .isEqualTo(LocalDateTime.of(2026, 11, 10, 8, 0, 0));
        assertThat(saved.get(0).getDeviceId()).isEqualTo("PLC-01");
        assertThat(saved.get(1).getStatus()).isEqualTo("FAILURE");
        verify(repository).saveAll(anyList());
    }

    @Test
    void keepsRawLineForForensicTraceability() throws IOException {
        String content = "2026-11-10 08:00:00,192.168.1.10,READ,SUCCESS,PLC-01\n";
        List<LogEntry> saved = service.parseAndSaveLogs(csv(content));
        assertThat(saved.get(0).getRawLine())
                .isEqualTo("2026-11-10 08:00:00,192.168.1.10,READ,SUCCESS,PLC-01");
    }

    @Test
    void supportsMultipleTimestampFormats() throws IOException {
        List<LogEntry> saved = service.parseAndSaveLogs(csv(
                "2026-11-10T09:30:00,192.168.1.5,WRITE,SUCCESS,PLC-01\n"));
        assertThat(saved.get(0).getTimestamp())
                .isEqualTo(LocalDateTime.of(2026, 11, 10, 9, 30, 0));
    }

    @Test
    void handlesEmptyFile() throws IOException {
        assertThat(service.parseAndSaveLogs(csv(""))).isEmpty();
    }
}
