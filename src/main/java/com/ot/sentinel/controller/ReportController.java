package com.ot.sentinel.controller;

import com.ot.sentinel.model.Incident;
import com.ot.sentinel.repository.IncidentRepository;
import com.ot.sentinel.repository.LogEntryRepository;
import com.ot.sentinel.service.ReportService;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

/**
 * PDF incident report generation endpoint.
 * Returns a downloadable forensic report (Apache PDFBox) covering every log
 * ingested so far plus all incidents currently flagged.
 */
@RestController
@RequestMapping("/api/report")
public class ReportController {

    private static final DateTimeFormatter FILE_TIMESTAMP = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss");

    private final ReportService reportService;
    private final LogEntryRepository logEntryRepository;
    private final IncidentRepository incidentRepository;

    public ReportController(ReportService reportService,
                            LogEntryRepository logEntryRepository,
                            IncidentRepository incidentRepository) {
        this.reportService = reportService;
        this.logEntryRepository = logEntryRepository;
        this.incidentRepository = incidentRepository;
    }

    @GetMapping(value = "/pdf", produces = MediaType.APPLICATION_PDF_VALUE)
    public ResponseEntity<byte[]> pdf() {
        List<Incident> incidents = incidentRepository.findByResolvedFalse();
        long total = logEntryRepository.count();
        long failures = logEntryRepository.countByStatus("FAILURE");
        long successes = logEntryRepository.countByStatus("SUCCESS");

        byte[] pdf = reportService.generateIncidentReport(incidents, total, failures, successes);

        // Timestamped file name so consecutive hand-over reports do not overwrite each other.
        String fileName = "ot-sentinel-incident-report-" + LocalDateTime.now().format(FILE_TIMESTAMP) + ".pdf";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_PDF);
        headers.setContentDisposition(ContentDisposition.builder("attachment").filename(fileName).build());
        headers.setContentLength(pdf.length);
        return ResponseEntity.ok().headers(headers).body(pdf);
    }
}
