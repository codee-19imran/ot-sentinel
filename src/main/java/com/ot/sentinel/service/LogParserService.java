package com.ot.sentinel.service;

import com.ot.sentinel.model.LogEntry;
import com.ot.sentinel.repository.LogEntryRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

/**
 * Parsing engine for raw OT/ICS log files (CSV/TXT exported from PLCs/RTUs).
 * Expected CSV: timestamp,sourceIp,command,status,deviceId
 */
@Service
public class LogParserService {

    private static final Logger log = LoggerFactory.getLogger(LogParserService.class);

    private final LogEntryRepository logEntryRepository;

    public LogParserService(LogEntryRepository logEntryRepository) {
        this.logEntryRepository = logEntryRepository;
    }

    /**
     * Parse the uploaded log file and persist every valid row.
     *
     * @param file the uploaded CSV/TXT log file
     * @return the list of persisted log entries
     * @throws IOException if the file cannot be read
     */
    public List<LogEntry> parseAndSaveLogs(MultipartFile file) throws IOException {
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(file.getInputStream(), StandardCharsets.UTF_8))) {
            return parseAndSave(reader, file.getOriginalFilename());
        }
    }

    /**
     * Parse already-normalized CSV text (e.g. produced by {@link RawLogNormalizerService}).
     *
     * @param csv        full CSV content including the header row
     * @param sourceName original file name, used for logging
     * @return the list of persisted log entries
     */
    public List<LogEntry> parseAndSaveCsv(String csv, String sourceName) throws IOException {
        return parseAndSave(new BufferedReader(new java.io.StringReader(csv)), sourceName);
    }

    /**
     * Core CSV row loop: reads rows, skips the header and malformed lines, persists the rest.
     */
    public List<LogEntry> parseAndSave(BufferedReader reader, String sourceName) throws IOException {
        List<LogEntry> entries = new ArrayList<>();
        int rejected = 0;

        String line;
        boolean skipHeader = true;
        while ((line = reader.readLine()) != null) {
            line = line.trim();
            if (line.isEmpty()) {
                continue;
            }
            // Detect and skip a header row such as "timestamp,sourceIp,command,status,deviceId"
            if (skipHeader && isHeader(line)) {
                skipHeader = false;
                continue;
            }
            skipHeader = false;

            String[] values = line.split(",", -1);
            if (values.length >= 5) {
                LogEntry entry = LogEntry.builder()
                        .timestamp(parseTimestamp(values[0].trim()))
                        .sourceIp(values[1].trim())
                        .commandType(values[2].trim())
                        .status(values[3].trim())
                        .deviceId(values[4].trim())
                        .rawLine(line)
                        .build();
                entries.add(entry);
            } else {
                rejected++;
                log.warn("{}: skipped malformed row: {}", sourceName, line);
            }
        }

        List<LogEntry> saved = logEntryRepository.saveAll(entries);
        log.info("Parsed {}: {} rows stored, {} malformed rows skipped",
                sourceName, saved.size(), rejected);
        return saved;
    }

    private boolean isHeader(String line) {
        String lower = line.toLowerCase();
        return lower.contains("timestamp") || lower.contains("sourceip") || lower.contains("deviceid");
    }

    private LocalDateTime parseTimestamp(String raw) {
        if (raw == null || raw.isBlank()) {
            return LocalDateTime.now();
        }
        String[] patterns = {
                "yyyy-MM-dd HH:mm:ss",
                "yyyy-MM-dd'T'HH:mm:ss",
                "yyyy-MM-dd HH:mm",
                "yyyy-MM-dd",
                "dd/MM/yyyy HH:mm",
                "MM/dd/yyyy HH:mm:ss"
        };
        for (String pattern : patterns) {
            try {
                return LocalDateTime.parse(raw, DateTimeFormatter.ofPattern(pattern));
            } catch (Exception ignored) {
                // try next pattern
            }
        }
        return LocalDateTime.now();
    }
}
