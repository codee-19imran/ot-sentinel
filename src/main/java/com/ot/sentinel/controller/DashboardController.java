package com.ot.sentinel.controller;

import com.ot.sentinel.model.Incident;
import com.ot.sentinel.model.LogEntry;
import com.ot.sentinel.repository.IncidentRepository;
import com.ot.sentinel.repository.LabelCount;
import com.ot.sentinel.repository.LogEntryRepository;
import com.ot.sentinel.service.AnomalyDetectionService;
import com.ot.sentinel.service.LogParserService;
import com.ot.sentinel.service.RawLogNormalizerService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Dashboard + log ingestion controller.
 * Serves the forensic dashboard and JSON chart data consumed by the frontend.
 *
 * <p>All chart data is aggregated by the database - no endpoint pulls the whole
 * log table into memory.</p>
 */
@Controller
public class DashboardController {

    private final LogEntryRepository logEntryRepository;
    private final IncidentRepository incidentRepository;
    private final LogParserService logParserService;
    private final RawLogNormalizerService rawLogNormalizerService;
    private final AnomalyDetectionService anomalyDetectionService;

    /** Whether the login screen may show the seeded demo credentials. */
    @Value("${ot-sentinel.demo.show-credentials:true}")
    private boolean showDemoCredentials;

    public DashboardController(LogEntryRepository logEntryRepository,
                               IncidentRepository incidentRepository,
                               LogParserService logParserService,
                               RawLogNormalizerService rawLogNormalizerService,
                               AnomalyDetectionService anomalyDetectionService) {
        this.logEntryRepository = logEntryRepository;
        this.incidentRepository = incidentRepository;
        this.logParserService = logParserService;
        this.rawLogNormalizerService = rawLogNormalizerService;
        this.anomalyDetectionService = anomalyDetectionService;
    }

    @GetMapping("/")
    public String root() {
        return "redirect:/login";
    }

    @GetMapping("/login")
    public String login(Model model) {
        model.addAttribute("showDemoCredentials", showDemoCredentials);
        return "login";
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

        // Newest 20 rows only - the database sorts, not the JVM.
        model.addAttribute("recentLogs", logEntryRepository.findTop20ByOrderByEventTimeDesc());
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
        return toRows(logEntryRepository.countByCommand(), "commandType", "count");
    }

    @GetMapping("/api/charts/status-distribution")
    @ResponseBody
    public List<Map<String, Object>> statusDistribution() {
        return toRows(logEntryRepository.countByStatusGrouped(), "status", "count");
    }

    @GetMapping("/api/charts/timeline")
    @ResponseBody
    public List<Map<String, Object>> timeline() {
        LocalDateTime now = LocalDateTime.now();
        LocalDateTime from = now.minusHours(23);

        // Only the timestamps of the last 24h are fetched (single column projection).
        Map<String, Long> buckets = logEntryRepository.findEventTimesBetween(from, now).stream()
                .filter(java.util.Objects::nonNull)
                .collect(Collectors.groupingBy(
                        e -> e.toLocalDate() + " " + String.format("%02d:00", e.getHour()),
                        Collectors.counting()));

        List<Map<String, Object>> result = new ArrayList<>();
        for (int h = 0; h < 24; h++) {
            LocalDateTime slot = now.minusHours(23 - h);
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
        return toRows(logEntryRepository.countBySourceIp(PageRequest.of(0, 10)), "ip", "count");
    }

    /**
     * Every distinct source address with its event count.
     * The threat map uses this instead of the top-10 list: a single connection
     * from an unusual network is exactly what a map must show, even when it
     * does not rank in the top ten.
     */
    @GetMapping("/api/charts/sources")
    @ResponseBody
    public List<Map<String, Object>> sources() {
        return toRows(logEntryRepository.countBySourceIp(PageRequest.of(0, 100)), "ip", "count");
    }

    @GetMapping("/api/charts/incident-severity")
    @ResponseBody
    public List<Map<String, Object>> incidentSeverity() {
        return toRows(incidentRepository.countBySeverityGrouped(), "severity", "count");
    }

    @GetMapping("/api/incidents")
    @ResponseBody
    public List<Incident> incidents() {
        return incidentRepository.findByResolvedFalse();
    }

    /** Maps grouped count rows onto the JSON shape expected by the charts. */
    private static List<Map<String, Object>> toRows(List<LabelCount> counts, String keyName, String valueName) {
        return counts.stream().map(c -> {
            Map<String, Object> row = new HashMap<>();
            row.put(keyName, c.getLabel());
            row.put(valueName, c.getTotal());
            return row;
        }).collect(Collectors.toList());
    }
}
