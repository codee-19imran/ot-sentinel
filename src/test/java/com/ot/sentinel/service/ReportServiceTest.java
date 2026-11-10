package com.ot.sentinel.service;

import com.ot.sentinel.model.Incident;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Smoke tests for Apache PDFBox incident report generation.
 */
class ReportServiceTest {

    private final ReportService service = new ReportService();

    private List<Incident> buildMany(int count) {
        List<Incident> list = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            list.add(Incident.builder()
                    .type("BRUTE_FORCE")
                    .severity(i % 2 == 0 ? "HIGH" : "MEDIUM")
                    .description("Test incident #" + (i + 1) + " from 10.0.0." + i)
                    .sourceIp("10.0.0." + i)
                    .detectedAt(LocalDateTime.of(2026, 11, 10, 12, 0))
                    .resolved(false)
                    .build());
        }
        return list;
    }

    @Test
    void producesValidPdfWithIncidents() {
        byte[] pdf = service.generateIncidentReport(
                buildMany(3), 150, 30, 120);

        assertThat(pdf).isNotNull().isNotEmpty();
        assertThat(new String(pdf, 0, 5, StandardCharsets.US_ASCII)).contains("%PDF");
        assertThat(pdf.length).isGreaterThan(1000);
    }

    @Test
    void paginatesForLargeIncidentSets() {
        byte[] pdf = service.generateIncidentReport(
                buildMany(40), 150, 30, 120);

        // more incidents than a single page can hold - PDF must still be produced
        assertThat(pdf).isNotNull();
        assertThat(new String(pdf, 0, 5, StandardCharsets.US_ASCII)).contains("%PDF");
    }

    @Test
    void handlesEmptyIncidentList() {
        byte[] pdf = service.generateIncidentReport(List.of(), 0, 0, 0);
        assertThat(pdf).isNotNull();
        assertThat(new String(pdf, 0, 5, StandardCharsets.US_ASCII)).contains("%PDF");
    }
}
