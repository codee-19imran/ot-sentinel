package com.ot.sentinel.service;

import com.ot.sentinel.model.Incident;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.font.Standard14Fonts;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

/**
 * Generates an offline, one-page PDF incident report using Apache PDFBox.
 * Suitable for air-gapped forensic handover to OT engineering/safety teams.
 */
@Service
public class ReportService {

    private static final DateTimeFormatter TS = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public byte[] generateIncidentReport(List<Incident> incidents,
                                         long totalLogs, long failures, long successes) {
        try (PDDocument document = new PDDocument();
             ByteArrayOutputStream baos = new ByteArrayOutputStream()) {

            PDPage page = new PDPage();
            document.addPage(page);

            float margin = 50f;
            float[] cursor = {page.getMediaBox().getHeight() - margin};

            try (PDPageContentStream cs = new PDPageContentStream(document, page)) {
                // ---------- Header ----------
                cs.beginText();
                cs.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA_BOLD), 20);
                cs.newLineAtOffset(margin, cursor[0]);
                cs.showText("OT-Sentinel - Offline Incident Response Report");
                cursor[0] -= 30;
                cs.endText();

                // ---------- Summary ----------
                cs.beginText();
                cs.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA), 12);
                cs.newLineAtOffset(margin, cursor[0]);
                cs.showText("Generated : " + LocalDateTime.now().format(TS));
                line(cs, cursor, 20);
                cs.showText("Total logs analysed   : " + totalLogs);
                line(cs, cursor, 18);
                cs.showText("Successful operations : " + successes);
                line(cs, cursor, 18);
                cs.showText("Failed operations     : " + failures);
                line(cs, cursor, 18);
                cs.showText(String.format("Failure rate          : %.1f%%",
                        totalLogs > 0 ? (failures * 100.0 / totalLogs) : 0.0));
                cursor[0] -= 26;
                cs.endText();

                // ---------- Incidents ----------
                cs.beginText();
                cs.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA_BOLD), 14);
                cs.newLineAtOffset(margin, cursor[0]);
                cs.showText("Detected Incidents");
                cursor[0] -= 20;
                cs.newLineAtOffset(0, -20);

                if (incidents == null || incidents.isEmpty()) {
                    cs.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA), 12);
                    cs.showText("No incidents detected.");
                } else {
                    for (Incident inc : incidents) {
                        cs.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA_BOLD), 12);
                        cs.showText("- [" + inc.getSeverity() + "] " + inc.getType());
                        cursor[0] -= 16;
                        cs.newLineAtOffset(0, -16);

                        cs.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA), 12);
                        String desc = inc.getDescription()
                                + (inc.getSourceIp() != null ? "  (source IP: " + inc.getSourceIp() + ")" : "");
                        cs.showText(desc);
                        cursor[0] -= 16;
                        cs.newLineAtOffset(0, -16);

                        cs.showText("  Detected at : " + inc.getDetectedAt().format(TS));
                        cursor[0] -= 22;
                        cs.newLineAtOffset(0, -22);
                    }
                }
                cs.endText();
            }

            document.save(baos);
            return baos.toByteArray();
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate PDF report", e);
        }
    }

    private static void line(PDPageContentStream cs, float[] cursor, float dy) throws IOException {
        cursor[0] -= dy;
        cs.newLineAtOffset(0, -dy);
    }
}
