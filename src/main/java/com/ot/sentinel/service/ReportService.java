package com.ot.sentinel.service;

import com.ot.sentinel.model.Incident;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.font.Standard14Fonts;
import org.springframework.stereotype.Service;

import java.awt.Color;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;

/**
 * Generates offline forensic incident reports with Apache PDFBox.
 * Layout: cover metrics, per-severity summary, colour-coded incident list,
 * automatic pagination and page footers. Suitable for air-gapped hand-over.
 */
@Service
public class ReportService {

    private static final DateTimeFormatter TS = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private static final float MARGIN = 50f;

    private static final PDType1Font HELVETICA = font(Standard14Fonts.FontName.HELVETICA);
    private static final PDType1Font HELVETICA_BOLD = font(Standard14Fonts.FontName.HELVETICA_BOLD);

    public byte[] generateIncidentReport(List<Incident> incidents,
                                         long totalLogs, long failures, long successes) {
        List<Incident> items = incidents == null ? List.of() : incidents;
        Map<String, Long> bySeverity = items.stream()
                .filter(i -> i.getSeverity() != null)
                .collect(java.util.stream.Collectors.groupingBy(
                        Incident::getSeverity, java.util.stream.Collectors.counting()));

        try (PDDocument document = new PDDocument();
             ByteArrayOutputStream baos = new ByteArrayOutputStream()) {

            boolean firstPage = true;
            int index = 0;
            int pageNo = 1;

            while (firstPage || index < items.size()) {
                PDPage page = new PDPage();
                document.addPage(page);

                float[] cursor = {page.getMediaBox().getHeight() - MARGIN};
                try (PDPageContentStream cs = new PDPageContentStream(document, page)) {

                    // ---------- Page header ----------
                    if (firstPage) {
                        heading(cs, cursor, 20, "OT-Sentinel - Offline Incident Response Report");
                    } else {
                        heading(cs, cursor, 16, "Detected Incidents (continued)");
                    }

                    // ---------- Summary metrics (first page only) ----------
                    if (firstPage) {
                        section(cs, cursor, 26);
                        line(cs, cursor, "Generated : " + LocalDateTime.now().format(TS), 20);
                        line(cs, cursor, "Total logs analysed   : " + totalLogs, 18);
                        line(cs, cursor, "Successful operations : " + successes, 18);
                        line(cs, cursor, "Failed operations     : " + failures, 18);
                        line(cs, cursor, String.format("Failure rate          : %.1f%%",
                                        totalLogs > 0 ? failures * 100.0 / totalLogs : 0.0), 18);
                        line(cs, cursor, "Incidents flagged     : " + items.size(), 24);

                        section(cs, cursor, "Severity breakdown", 20);
                        line(cs, cursor, "  CRITICAL : " + bySeverity.getOrDefault("CRITICAL", 0L), 16);
                        line(cs, cursor, "  HIGH     : " + bySeverity.getOrDefault("HIGH", 0L), 16);
                        line(cs, cursor, "  MEDIUM   : " + bySeverity.getOrDefault("MEDIUM", 0L), 16);
                        line(cs, cursor, "  LOW      : " + bySeverity.getOrDefault("LOW", 0L), 24);
                    }

                    // ---------- Incident list ----------
                    String nextHeading = "Detected Incidents";
                    while (index < items.size() && cursor[0] > MARGIN + 90) {
                        Incident inc = items.get(index);
                        spacer(cs, cursor, 14);

                        severityTag(cs, cursor, nextHeading.equals("Detected Incidents") && firstPage
                                ? "Detected Incidents" : nextHeading, inc);
                        nextHeading = "";
                        line(cs, cursor, "  " + inc.getDescription()
                                + (inc.getSourceIp() != null ? "  (source IP: " + inc.getSourceIp() + ")" : ""), 16);
                        line(cs, cursor, "  Detected at : " +
                                (inc.getDetectedAt() != null ? inc.getDetectedAt().format(TS) : "-"), 22);
                        index++;
                    }

                    if (index < items.size()) {
                        line(cs, cursor, "... report continues on the next page", 16);
                    }

                    // ---------- Footer ----------
                    footer(cs, page, pageNo);
                }

                firstPage = false;
                pageNo++;
            }

            document.save(baos);
            return baos.toByteArray();
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate PDF report", e);
        }
    }

    /* ---------- low-level helper methods ---------- */

    private static PDType1Font font(Standard14Fonts.FontName name) {
        return new PDType1Font(name);
    }

    private static void heading(PDPageContentStream cs, float[] cursor, float size, String text) throws IOException {
        cs.beginText();
        cs.setFont(HELVETICA_BOLD, size);
        cs.newLineAtOffset(MARGIN, cursor[0]);
        cs.showText(text);
        cursor[0] -= (size + 10);
        cs.endText();
    }

    private static void section(PDPageContentStream cs, float[] cursor, float dy) throws IOException {
        cursor[0] -= dy;
    }

    private static void section(PDPageContentStream cs, float[] cursor, String text, float dy) throws IOException {
        cs.beginText();
        cs.setFont(HELVETICA_BOLD, 14);
        cs.newLineAtOffset(MARGIN, cursor[0]);
        cs.showText(text);
        cursor[0] -= dy;
        cs.endText();
    }

    private static void line(PDPageContentStream cs, float[] cursor, String text, float dy) throws IOException {
        cs.beginText();
        cs.setFont(HELVETICA, 12);
        cs.newLineAtOffset(MARGIN, cursor[0]);
        cs.showText(text);
        cursor[0] -= dy;
        cs.endText();
    }

    private static void spacer(PDPageContentStream cs, float[] cursor, float dy) {
        cursor[0] -= dy;
    }

    private static void severityTag(PDPageContentStream cs, float[] cursor, String headingLabel,
                                    Incident inc) throws IOException {
        Color color = switch (inc.getSeverity() == null ? "" : inc.getSeverity().toUpperCase()) {
            case "CRITICAL", "HIGH" -> new Color(203, 33, 50);
            case "MEDIUM"           -> new Color(217, 143, 15);
            default                 -> new Color(22, 101, 87);
        };

        if (headingLabel != null && !headingLabel.isBlank()) {
            cs.beginText();
            cs.setFont(HELVETICA_BOLD, 14);
            cs.setNonStrokingColor(new Color(15, 23, 42));
            cs.newLineAtOffset(MARGIN, cursor[0]);
            cs.showText(headingLabel);
            cs.endText();
            cursor[0] -= 16;
        }

        cs.beginText();
        cs.setFont(HELVETICA_BOLD, 12);
        cs.setNonStrokingColor(color);
        cs.newLineAtOffset(MARGIN, cursor[0]);
        cs.showText("- [" + inc.getSeverity() + "] " + inc.getType());
        cs.setNonStrokingColor(Color.BLACK);
        cursor[0] -= 16;
        cs.endText();
    }

    private static void footer(PDPageContentStream cs, PDPage page, int pageNo) throws IOException {
        cs.beginText();
        cs.setFont(HELVETICA, 9);
        cs.setNonStrokingColor(new Color(100, 116, 139));
        cs.newLineAtOffset(MARGIN, MARGIN / 2);
        cs.showText("Generated by OT-Sentinel — Offline Incident Response & Log Forensics Dashboard");
        cs.endText();

        cs.beginText();
        cs.setFont(HELVETICA, 9);
        cs.setNonStrokingColor(new Color(100, 116, 139));
        cs.newLineAtOffset(page.getMediaBox().getWidth() - MARGIN - 40, MARGIN / 2);
        cs.showText("page " + pageNo);
        cs.endText();
        cs.setNonStrokingColor(Color.BLACK);
    }
}
