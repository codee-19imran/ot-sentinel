package com.ot.sentinel.service;

import com.ot.sentinel.model.Incident;
import com.ot.sentinel.model.LogEntry;
import com.ot.sentinel.repository.IncidentRepository;
import com.ot.sentinel.repository.LogEntryRepository;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * The "brain" of OT-Sentinel: a simple rule-based anomaly detection engine.
 * Rules run locally against the parsed logs - no cloud connectivity required.
 */
@Service
public class AnomalyDetectionService {

    private final LogEntryRepository logEntryRepository;
    private final IncidentRepository incidentRepository;

    public AnomalyDetectionService(LogEntryRepository logEntryRepository,
                                   IncidentRepository incidentRepository) {
        this.logEntryRepository = logEntryRepository;
        this.incidentRepository = incidentRepository;
    }

    /**
     * Brute-force rule: more than `threshold` failed logins from one IP
     * within `windowMinutes` minutes => HIGH severity incident.
     */
    public List<Incident> detectBruteForce(int threshold, int windowMinutes) {
        LocalDateTime since = LocalDateTime.now().minusMinutes(windowMinutes);
        List<LogEntry> failures = logEntryRepository.findByStatus("FAILURE").stream()
                .filter(e -> e.getTimestamp() != null && !e.getTimestamp().isBefore(since))
                .collect(Collectors.toList());

        Map<String, Long> perIp = failures.stream()
                .filter(e -> e.getSourceIp() != null)
                .collect(Collectors.groupingBy(LogEntry::getSourceIp, Collectors.counting()));

        List<Incident> incidents = new ArrayList<>();
        perIp.forEach((ip, count) -> {
            if (count > threshold) {
                incidents.add(Incident.builder()
                        .type("BRUTE_FORCE")
                        .severity("HIGH")
                        .description("Brute-force login: " + count
                                + " failed attempts from " + ip
                                + " in the last " + windowMinutes + " minutes")
                        .sourceIp(ip)
                        .detectedAt(LocalDateTime.now())
                        .resolved(false)
                        .build());
            }
        });
        return incidentRepository.saveAll(incidents);
    }

    /**
     * Unusual-command rule: STOP / DELETE / RESET commands from a single source
     * are flagged as MEDIUM severity (possible unauthorised control operation).
     */
    public List<Incident> detectUnusualCommands() {
        List<String> unusualCommands = List.of("STOP", "DELETE", "RESET", "SHUTDOWN");
        List<LogEntry> unusual = logEntryRepository.findAll().stream()
                .filter(e -> e.getCommandType() != null
                        && unusualCommands.contains(e.getCommandType().toUpperCase()))
                .collect(Collectors.toList());

        Map<String, List<LogEntry>> perIp = unusual.stream()
                .filter(e -> e.getSourceIp() != null)
                .collect(Collectors.groupingBy(LogEntry::getSourceIp));

        List<Incident> incidents = new ArrayList<>();
        perIp.forEach((ip, entries) -> {
            incidents.add(Incident.builder()
                    .type("UNUSUAL_COMMAND")
                    .severity("MEDIUM")
                    .description("Unusual control command(s) from " + ip
                            + " (" + entries.size() + " occurrence(s): "
                            + entries.stream().map(LogEntry::getCommandType)
                            .collect(Collectors.joining(", ")) + ")")
                    .sourceIp(ip)
                    .detectedAt(LocalDateTime.now())
                    .resolved(false)
                    .build());
        });
        return incidentRepository.saveAll(incidents);
    }

    /**
     * Run all detection rules. Previous detections are cleared so the dashboard
     * always reflects the current rule set over the currently stored logs.
     */
    public List<Incident> detectAll() {
        incidentRepository.deleteAll();
        List<Incident> all = new ArrayList<>();
        all.addAll(detectBruteForce(5, 60));
        all.addAll(detectUnusualCommands());
        return all;
    }
}
