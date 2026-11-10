package com.ot.sentinel.controller;

import com.ot.sentinel.model.Incident;
import com.ot.sentinel.model.LogEntry;
import com.ot.sentinel.service.AnomalyDetectionService;
import com.ot.sentinel.service.LogParserService;
import com.ot.sentinel.service.RawLogNormalizerService;
import com.ot.sentinel.service.ReportService;
import com.ot.sentinel.repository.IncidentRepository;
import com.ot.sentinel.repository.LogEntryRepository;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Dashboard + log ingestion controller.
 * Serves the forensic dashboard and JSON chart data consumed by the frontend.
 */
@Controller
public class DashboardController {

    @GetMapping("/")
    public String root() {
        return "redirect:/login";
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    private final LogEntryRepository logEntryRepository;
    private final IncidentRepository incidentRepository;
    private final LogParserService logParserService;
    private final RawLogNormalizerService rawLogNormalizerService;
    private final AnomalyDetectionService anomalyDetectionService;
    private final ReportService reportService;

    public DashboardController(LogEntryRepository logEntryRepository,
                               IncidentRepository incidentRepository,
                               LogParserService logParserService,
                               RawLogNormalizerService rawLogNormalizerService,
                               AnomalyDetectionService anomalyDetectionService,
                               ReportService reportService) {
        this.logEntryRepository = logEntryRepository;
        this.incidentRepository = incidentRepository;
        this.logParserService = logParserService;
        this.rawLogNormalizerService = rawLogNormalizerService;
        this.anomalyDetectionService = anomalyDetectionService;
        this.reportService = reportService;
    }

    @GetMapping("/dashboard")
    public String dashboard(Model model) {
        long total = logEntryRepository.count();
        long failures = logEntryRepository.countByStatus("FAILURE");
        long successes = logEntryRepository.countByStatus("SUCCESS");
        List<Incident> incidents = incidentRepository.findByResolvedFalse();

        model.addAttribute("totalLogs", total);
        model.addAttribute("failures", failures);
        model.addAttribute("successes", successes);
        model.addAttribute("failureRate", total > 0 ? String.format("%.1f", failures * 100.0 / total) : "0.0");
        model.addAttribute("incidents", incidents);
        model.addAttribute("highSeverity",
                incidents.stream().filter(i -> "HIGH".equals(i.getSeverity()) || "CRITICAL".equals(i.getSeverity())).count());

        List<LogEntry> recentLogs = logEntryRepository.findAll().stream()
                .filter(e -> e.getTimestamp() != null)
                .sorted(java.util.Comparator.comparing(LogEntry::getTimestamp).reversed())
                .limit(20)
                .collect(Collectors.toList());
        model.addAttribute("recentLogs", recentLogs);
        return "dashboard";
    }

    // ---------- Log ingestion ----------
    @PostMapping("/logs/upload")
    public String uploadLogs(@RequestParam("file") MultipartFile file,
                             RedirectAttributes redirect) {
        try {
            List<LogEntry> saved = logParserService.parseAndSaveLogs(file);
            List<Incident> incidents = anomalyDetectionService.detectAll();
            redirect.addFlashAttribute("success",
                    "Log file \"" + file.getOriginalFilename() + "\": " + saved.size()
                            + " row(s) parsed, " + incidents.size() + " incident(s) flagged by the rule engine.");
        } catch (Exception e) {
            redirect.addFlashAttribute("error", "Failed to parse log file: " + e.getMessage());
        }
        return "redirect:/dashboard";
    }

    @PostMapping("/logs/upload-raw")
    public String uploadRawLogs(@RequestParam("file") MultipartFile file,
                                RedirectAttributes redirect) {
        try {
            List<LogEntry> saved = rawLogNormalizerService.ingestRawLogs(file);
            List<Incident> incidents = anomalyDetectionService.detectAll();
            redirect.addFlashAttribute("success",
                    "Raw log file \"" + file.getOriginalFilename() + "\" normalised: " + saved.size()
                            + " row(s) ingested, " + incidents.size() + " incident(s) flagged by the rule engine.");
        } catch (Exception e) {
            redirect.addFlashAttribute("error", "Failed to normalise raw log file: " + e.getMessage());
        }
        return "redirect:/dashboard";
    }

    @PostMapping("/incidents/detect")
    public String rerunDetection(RedirectAttributes redirect) {
        List<Incident> incidents = anomalyDetectionService.detectAll();
        redirect.addFlashAttribute("info",
                "Re-scan complete: rules re-run over all " + logEntryRepository.count()
                        + " stored log(s) - " + incidents.size() + " incident(s) flagged.");
        return "redirect:/dashboard";
    }

    // ---------- Chart data (JSON) ----------
    @GetMapping("/api/charts/command-frequency")
    @ResponseBody
    public List<Map<String, Object>> commandFrequency() {
        return groupBy(logEntryRepository.findAll(), LogEntry::getCommandType, "commandType", "count");
    }

    @GetMapping("/api/charts/status-distribution")
    @ResponseBody
    public List<Map<String, Object>> statusDistribution() {
        return groupBy(logEntryRepository.findAll(), LogEntry::getStatus, "status", "count");
    }

    @GetMapping("/api/charts/timeline")
    @ResponseBody
    public List<Map<String, Object>> timeline() {
        java.time.LocalDateTime now = java.time.LocalDateTime.now();
        java.time.LocalDateTime from = now.minusHours(24);

        Map<String, Long> buckets = logEntryRepository.findAll().stream()
                .filter(e -> e.getTimestamp() != null && !e.getTimestamp().isBefore(from) && !e.getTimestamp().isAfter(now))
                .collect(Collectors.groupingBy(
                        e -> e.getTimestamp().toLocalDate() + " " + String.format("%02d:00", e.getTimestamp().getHour()),
                        Collectors.counting()));

        List<Map<String, Object>> result = new java.util.ArrayList<>();
        for (int h = 0; h < 24; h++) {
            java.time.LocalDateTime slot = now.minusHours(23 - h);
            String label = slot.toLocalDate() + " " + String.format("%02d:00", slot.getHour());
            Map<String, Object> row = new HashMap<>();
            row.put("hour", label);
            row.put("count", buckets.getOrDefault(label, 0L));
            result.add(row);
        }
        return result;
    }

    @GetMapping("/api/charts/top-ips")
    @ResponseBody
    public List<Map<String, Object>> topIps() {
        return logEntryRepository.findAll().stream()
                .filter(e -> e.getSourceIp() != null)
                .collect(Collectors.groupingBy(com.ot.sentinel.model.LogEntry::getSourceIp, Collectors.counting()))
                .entrySet().stream()
                .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
                .limit(10)
                .map(e -> {
                    Map<String, Object> row = new HashMap<>();
                    row.put("ip", e.getKey());
                    row.put("count", e.getValue());
                    return row;
                })
                .collect(Collectors.toList());
    }

    @GetMapping("/api/charts/incident-severity")
    @ResponseBody
    public List<Map<String, Object>> incidentSeverity() {
        return incidentRepository.findAll().stream()
                .filter(i -> i.getSeverity() != null)
                .collect(Collectors.groupingBy(com.ot.sentinel.model.Incident::getSeverity, Collectors.counting()))
                .entrySet().stream()
                .map(e -> {
                    Map<String, Object> row = new HashMap<>();
                    row.put("severity", e.getKey());
                    row.put("count", e.getValue());
                    return row;
                })
                .collect(Collectors.toList());
    }

    @GetMapping("/api/incidents")
    @ResponseBody
    public List<Incident> incidents() {
        return incidentRepository.findByResolvedFalse();
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> groupBy(List<com.ot.sentinel.model.LogEntry> entries,
                                                     java.util.function.Function<com.ot.sentinel.model.LogEntry, String> keyFn,
                                                     String keyName, String valueName) {
        return entries.stream()
                .filter(e -> keyFn.apply(e) != null)
                .collect(Collectors.groupingBy(keyFn, Collectors.counting()))
                .entrySet().stream()
                .map(e -> {
                    Map<String, Object> row = new HashMap<>();
                    row.put(keyName, e.getKey());
                    row.put(valueName, e.getValue());
                    return row;
                })
                .collect(Collectors.toList());
    }
}
