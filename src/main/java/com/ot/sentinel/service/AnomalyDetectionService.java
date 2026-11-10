package com.ot.sentinel.service;

import com.ot.sentinel.model.Incident;
import com.ot.sentinel.model.LogEntry;
import com.ot.sentinel.repository.IncidentRepository;
import com.ot.sentinel.repository.LogEntryRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * The "brain" of OT-Sentinel: a rule-based anomaly detection engine.
 * All rules run locally against the parsed logs - no cloud connectivity required.
 * Thresholds are configurable in application.properties:
 * <pre>
 * ot-sentinel.rules.brute-force-threshold      (default 5)
 * ot-sentinel.rules.brute-force-window-minutes (default 60)
 * ot-sentinel.rules.off-hours                  (default 0-5)
 * </pre>
 */
@Service
public class AnomalyDetectionService {

    private static final Logger log = LoggerFactory.getLogger(AnomalyDetectionService.class);

    private final LogEntryRepository logEntryRepository;
    private final IncidentRepository incidentRepository;

    private final int bruteForceThreshold;
    private final int bruteForceWindowMinutes;
    private final String offHours;

    public AnomalyDetectionService(LogEntryRepository logEntryRepository,
                                   IncidentRepository incidentRepository,
                                   @Value("${ot-sentinel.rules.brute-force-threshold:5}") int bruteForceThreshold,
                                   @Value("${ot-sentinel.rules.brute-force-window-minutes:60}") int bruteForceWindowMinutes,
                                   @Value("${ot-sentinel.rules.off-hours:0-5}") String offHours) {
        this.logEntryRepository = logEntryRepository;
        this.incidentRepository = incidentRepository;
        this.bruteForceThreshold = bruteForceThreshold;
        this.bruteForceWindowMinutes = bruteForceWindowMinutes;
        this.offHours = offHours;
    }

    /**
     * Brute-force rule: more than {@code threshold} failed logins from one IP
     * within the time window => HIGH severity incident.
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
        return incidents;
    }

    /**
     * Unusual-command rule: STOP / DELETE / RESET / SHUTDOWN commands from one source
     * are flagged as MEDIUM severity (possible unauthorised control operation).
     */
    public List<Incident> detectUnusualCommands() {
        List<String> unusualCommands = List.of("STOP", "DELETE", "RESET", "SHUTDOWN");
        Map<String, List<LogEntry>> perIp = logEntryRepository.findAll().stream()
                .filter(e -> e.getCommandType() != null
                        && unusualCommands.contains(e.getCommandType().toUpperCase()))
                .filter(e -> e.getSourceIp() != null)
                .collect(Collectors.groupingBy(LogEntry::getSourceIp));

        List<Incident> incidents = new ArrayList<>();
        perIp.forEach((ip, entries) -> incidents.add(Incident.builder()
                .type("UNUSUAL_COMMAND")
                .severity("MEDIUM")
                .description("Unusual control command(s) from " + ip
                        + " (" + entries.size() + " occurrence(s): "
                        + entries.stream().map(LogEntry::getCommandType).collect(Collectors.joining(", ")) + ")")
                .sourceIp(ip)
                .detectedAt(LocalDateTime.now())
                .resolved(false)
                .build()));
        return incidents;
    }

    /**
     * Off-hours rule: commands issued outside plant working hours (default 00:00-05:59)
     * by an unfamiliar source => MEDIUM severity (possible out-of-band manipulation).
     */
    public List<Incident> detectOffHoursActivity() {
        final int startHour, endHour;
        try {
            String[] parts = offHours.split("-");
            startHour = Integer.parseInt(parts[0].trim());
            endHour = Integer.parseInt(parts[1].trim());
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid ot-sentinel.rules.off-hours format (expected e.g. \"0-5\")", e);
        }

        Map<String, List<LogEntry>> perIp = logEntryRepository.findAll().stream()
                .filter(e -> e.getTimestamp() != null)
                .filter(e -> {
                    int hour = e.getTimestamp().getHour();
                    return hour >= startHour && hour <= endHour;
                })
                .filter(e -> e.getSourceIp() != null)
                .collect(Collectors.groupingBy(LogEntry::getSourceIp));

        List<Incident> incidents = new ArrayList<>();
        perIp.forEach((ip, entries) -> {
            if (entries.size() >= 3) {
                incidents.add(Incident.builder()
                        .type("OFF_HOURS_ACTIVITY")
                        .severity("MEDIUM")
                        .description("Off-hours activity from " + ip + ": " + entries.size()
                                + " commands between " + String.format("%02d:00", startHour)
                                + " and " + String.format("%02d:59", endHour))
                        .sourceIp(ip)
                        .detectedAt(LocalDateTime.now())
                        .resolved(false)
                        .build());
            }
        });
        return incidents;
    }

    /**
     * Run every detection rule over the currently stored logs.
     * Previous detections are cleared so the dashboard always reflects
     * the current rule set.
     */
    public List<Incident> detectAll() {
        incidentRepository.deleteAll();
        List<Incident> all = new ArrayList<>();
        all.addAll(detectBruteForce(bruteForceThreshold, bruteForceWindowMinutes));
        all.addAll(detectUnusualCommands());
        all.addAll(detectOffHoursActivity());

        List<Incident> saved = incidentRepository.saveAll(all);
        log.info("Anomaly detection: {} rule(s) applied, {} incident(s) flagged", 3, saved.size());
        return saved;
    }
}
