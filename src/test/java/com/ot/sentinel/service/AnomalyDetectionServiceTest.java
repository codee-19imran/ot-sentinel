package com.ot.sentinel.service;

import com.ot.sentinel.model.Incident;
import com.ot.sentinel.model.LogEntry;
import com.ot.sentinel.repository.IncidentRepository;
import com.ot.sentinel.repository.LogEntryRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the rule-based anomaly detection engine.
 */
class AnomalyDetectionServiceTest {

    private LogEntryRepository logs;
    private IncidentRepository incidents;
    private AnomalyDetectionService service;

    private static final LogEntry EMPTY_ENTRY_UNUSED = null; // readability helper only

    @BeforeEach
    void setUp() {
        logs = mock(LogEntryRepository.class);
        incidents = mock(IncidentRepository.class);
        service = new AnomalyDetectionService(logs, incidents, 5, 60, "0-5");
        when(incidents.saveAll(anyList())).thenAnswer(inv -> inv.getArgument(0));
        doNothing().when(incidents).deleteAll();
    }

    private LogEntry entry(String ip, String cmd, String status, LocalDateTime ts) {
        return LogEntry.builder().sourceIp(ip).commandType(cmd).status(status).timestamp(ts).build();
    }

    @Test
    void bruteForceFlagsIpsBeyondThreshold() {
        LocalDateTime ts = LocalDateTime.now().minusMinutes(10);
        when(logs.findByStatus("FAILURE")).thenReturn(IntStream.range(0, 6)
                .mapToObj(i -> entry("10.0.0.99", "LOGIN", "FAILURE", ts.plusSeconds(i)))
                .collect(Collectors.toList()));

        List<Incident> result = service.detectBruteForce(5, 60);

        assertThat(result).hasSize(1);
        assertThat(result.get(0).getType()).isEqualTo("BRUTE_FORCE");
        assertThat(result.get(0).getSeverity()).isEqualTo("HIGH");
        assertThat(result.get(0).getSourceIp()).isEqualTo("10.0.0.99");
    }

    @Test
    void bruteForceIgnoresFailuresOutsideWindow() {
        when(logs.findByStatus("FAILURE")).thenReturn(IntStream.range(0, 6)
                .mapToObj(i -> entry("10.0.0.99", "LOGIN", "FAILURE", LocalDateTime.now().minusHours(2)))
                .collect(Collectors.toList()));

        assertThat(service.detectBruteForce(5, 60)).isEmpty();
    }

    @Test
    void bruteForceIgnoresIpsUnderThreshold() {
        LocalDateTime ts = LocalDateTime.now();
        when(logs.findByStatus("FAILURE")).thenReturn(List.of(
                entry("a", "LOGIN", "FAILURE", ts), entry("a", "LOGIN", "FAILURE", ts)));

        assertThat(service.detectBruteForce(5, 60)).isEmpty();
    }

    @Test
    void unusualCommandsFlagSuspects() {
        LocalDateTime now = LocalDateTime.now();
        when(logs.findAll()).thenReturn(List.of(
                entry("10.0.0.99", "STOP", "FAILURE", now),
                entry("10.0.0.99", "STOP", "SUCCESS", now),
                entry("10.0.0.99", "READ", "SUCCESS", now)));

        List<Incident> result = service.detectUnusualCommands();

        assertThat(result).hasSize(1);
        assertThat(result.get(0).getType()).isEqualTo("UNUSUAL_COMMAND");
        assertThat(result.get(0).getSeverity()).isEqualTo("MEDIUM");
    }

    @Test
    void offHoursFlagsRecurringNightTraffic() {
        when(logs.findAll()).thenReturn(List.of(
                entry("172.16.0.44", "READ", "SUCCESS",
                        LocalDateTime.of(2026, 11, 10, 3, 0)),
                entry("172.16.0.44", "WRITE", "SUCCESS",
                        LocalDateTime.of(2026, 11, 10, 4, 30)),
                entry("172.16.0.44", "READ", "SUCCESS",
                        LocalDateTime.of(2026, 11, 10, 5, 59))));

        List<Incident> result = service.detectOffHoursActivity();

        assertThat(result).hasSize(1);
        assertThat(result.get(0).getType()).isEqualTo("OFF_HOURS_ACTIVITY");
    }

    @Test
    void offHoursIgnoresBusinessHours() {
        when(logs.findAll()).thenReturn(List.of(
                entry("172.16.0.44", "READ", "SUCCESS",
                        LocalDateTime.of(2026, 11, 10, 12, 0)),
                entry("172.16.0.44", "WRITE", "SUCCESS",
                        LocalDateTime.of(2026, 11, 10, 13, 0)),
                entry("172.16.0.44", "READ", "SUCCESS",
                        LocalDateTime.of(2026, 11, 10, 14, 0))));

        assertThat(service.detectOffHoursActivity()).isEmpty();
    }

    @Test
    void detectAllClearsPreviousAndRunsEveryRule() {
        LocalDateTime now = LocalDateTime.now();
        when(logs.findByStatus("FAILURE")).thenReturn(List.of());
        when(logs.findAll()).thenReturn(List.of(
                entry("10.0.0.99", "STOP", "FAILURE", now),
                entry("172.16.0.44", "READ", "SUCCESS", LocalDateTime.of(2026, 11, 10, 1, 0)),
                entry("172.16.0.44", "READ", "SUCCESS", LocalDateTime.of(2026, 11, 10, 2, 0)),
                entry("172.16.0.44", "READ", "SUCCESS", LocalDateTime.of(2026, 11, 10, 3, 0))));

        List<Incident> result = service.detectAll();

        assertThat(result).anySatisfy(i -> assertThat(i.getType()).isEqualTo("UNUSUAL_COMMAND"));
        assertThat(result).anySatisfy(i -> assertThat(i.getType()).isEqualTo("OFF_HOURS_ACTIVITY"));
        verify(incidents).deleteAll();
        verify(incidents).saveAll(anyList());
    }
}
