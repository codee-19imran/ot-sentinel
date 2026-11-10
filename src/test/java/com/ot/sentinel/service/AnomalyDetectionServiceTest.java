package com.ot.sentinel.service;

import com.ot.sentinel.model.Incident;
import com.ot.sentinel.repository.IncidentRepository;
import com.ot.sentinel.repository.LabelCount;
import com.ot.sentinel.repository.LogEntryRepository;
import com.ot.sentinel.repository.LogRow;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.List;

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

    @BeforeEach
    void setUp() {
        logs = mock(LogEntryRepository.class);
        incidents = mock(IncidentRepository.class);
        service = new AnomalyDetectionService(logs, incidents, 5, 60, "0-5");
        when(incidents.saveAll(anyList())).thenAnswer(inv -> inv.getArgument(0));
        doNothing().when(incidents).deleteAll();
        when(logs.countFailuresPerIpSince(org.mockito.ArgumentMatchers.any()))
                .thenReturn(List.of());
        when(logs.findByCommandTypes(anyList())).thenReturn(List.of());
        when(logs.findSourceAndEventTimes()).thenReturn(List.of());
    }

    private static LabelCount labelCount(String label, long total) {
        return new LabelCount() {
            @Override
            public String getLabel() {
                return label;
            }

            @Override
            public long getTotal() {
                return total;
            }
        };
    }

    private static LogRow logRow(String ip, String command, LocalDateTime eventTime) {
        return new LogRow() {
            @Override
            public String getSourceIp() {
                return ip;
            }

            @Override
            public String getCommandType() {
                return command;
            }

            @Override
            public LocalDateTime getEventTime() {
                return eventTime;
            }
        };
    }

    @Test
    void bruteForceFlagsIpsBeyondThreshold() {
        when(logs.countFailuresPerIpSince(org.mockito.ArgumentMatchers.any()))
                .thenReturn(List.of(labelCount("10.0.0.99", 6)));

        List<Incident> result = service.detectBruteForce(5, 60);

        assertThat(result).hasSize(1);
        assertThat(result.get(0).getType()).isEqualTo("BRUTE_FORCE");
        assertThat(result.get(0).getSeverity()).isEqualTo("HIGH");
        assertThat(result.get(0).getSourceIp()).isEqualTo("10.0.0.99");
        assertThat(result.get(0).getDescription()).contains("6 failed attempts");
    }

    @Test
    void bruteForceIgnoresIpsUnderThreshold() {
        when(logs.countFailuresPerIpSince(org.mockito.ArgumentMatchers.any()))
                .thenReturn(List.of(labelCount("10.0.0.99", 3)));

        assertThat(service.detectBruteForce(5, 60)).isEmpty();
    }

    @Test
    void unusualCommandsFlagSuspects() {
        when(logs.findByCommandTypes(anyList())).thenReturn(List.of(
                logRow("10.0.0.99", "STOP", LocalDateTime.now()),
                logRow("10.0.0.99", "SHUTDOWN", LocalDateTime.now())));

        List<Incident> result = service.detectUnusualCommands();

        assertThat(result).hasSize(1);
        assertThat(result.get(0).getType()).isEqualTo("UNUSUAL_COMMAND");
        assertThat(result.get(0).getSeverity()).isEqualTo("MEDIUM");
        assertThat(result.get(0).getSourceIp()).isEqualTo("10.0.0.99");
        assertThat(result.get(0).getDescription()).contains("2 occurrence(s)");
    }

    @Test
    void offHoursFlagsRecurringNightTraffic() {
        when(logs.findSourceAndEventTimes()).thenReturn(List.of(
                logRow("172.16.0.44", "READ", LocalDateTime.of(2026, 11, 10, 3, 0)),
                logRow("172.16.0.44", "WRITE", LocalDateTime.of(2026, 11, 10, 4, 30)),
                logRow("172.16.0.44", "READ", LocalDateTime.of(2026, 11, 10, 5, 59))));

        List<Incident> result = service.detectOffHoursActivity();

        assertThat(result).hasSize(1);
        assertThat(result.get(0).getType()).isEqualTo("OFF_HOURS_ACTIVITY");
    }

    @Test
    void offHoursIgnoresBusinessHours() {
        when(logs.findSourceAndEventTimes()).thenReturn(List.of(
                logRow("172.16.0.44", "READ", LocalDateTime.of(2026, 11, 10, 12, 0)),
                logRow("172.16.0.44", "WRITE", LocalDateTime.of(2026, 11, 10, 13, 0)),
                logRow("172.16.0.44", "READ", LocalDateTime.of(2026, 11, 10, 14, 0))));

        assertThat(service.detectOffHoursActivity()).isEmpty();
    }

    @Test
    void detectAllClearsPreviousAndRunsEveryRule() {
        when(logs.countFailuresPerIpSince(org.mockito.ArgumentMatchers.any()))
                .thenReturn(List.of(labelCount("192.168.1.50", 9)));
        when(logs.findByCommandTypes(anyList())).thenReturn(List.of(
                logRow("10.0.0.99", "STOP", LocalDateTime.now())));
        when(logs.findSourceAndEventTimes()).thenReturn(List.of(
                logRow("172.16.0.44", "READ", LocalDateTime.of(2026, 11, 10, 1, 0)),
                logRow("172.16.0.44", "READ", LocalDateTime.of(2026, 11, 10, 2, 0)),
                logRow("172.16.0.44", "READ", LocalDateTime.of(2026, 11, 10, 3, 0))));

        List<Incident> result = service.detectAll();

        assertThat(result).anySatisfy(i -> assertThat(i.getType()).isEqualTo("BRUTE_FORCE"));
        assertThat(result).anySatisfy(i -> assertThat(i.getType()).isEqualTo("UNUSUAL_COMMAND"));
        assertThat(result).anySatisfy(i -> assertThat(i.getType()).isEqualTo("OFF_HOURS_ACTIVITY"));
        verify(incidents).deleteAll();
        verify(incidents).saveAll(anyList());
    }

    @Test
    void unusualCommandQueryIsScopedToControlCommands() {
        service.detectUnusualCommands();

        org.mockito.ArgumentCaptor<List<String>> captor = org.mockito.ArgumentCaptor.forClass(List.class);
        verify(logs).findByCommandTypes(captor.capture());
        assertThat(captor.getValue()).contains("STOP", "DELETE", "RESET", "SHUTDOWN");
    }

    @Test
    void invalidOffHoursConfigurationFailsFast() {
        AnomalyDetectionService broken = new AnomalyDetectionService(logs, incidents, 5, 60, "nonsense");

        org.assertj.core.api.Assertions.assertThatThrownBy(broken::detectOffHoursActivity)
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("off-hours");
    }
}
