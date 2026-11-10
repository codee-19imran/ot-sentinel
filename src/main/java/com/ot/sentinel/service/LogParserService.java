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
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

/**
 * Parsing engine for raw OT/ICS log files (CSV exported from PLCs/RTUs).
 * Expected CSV: timestamp,sourceIp,command,status,deviceId
 */
@Service
public class LogParserService {

    private static final Logger log = LoggerFactory.getLogger(LogParserService.class);

    /** Accepted timestamp formats, tried in order. */
    private static final String[] TIMESTAMP_PATTERNS = {
            "yyyy-MM-dd HH:mm:ss",
            "yyyy-MM-dd'T'HH:mm:ss",
            "yyyy-MM-dd HH:mm",
            "yyyy-MM-dd",
            "dd/MM/yyyy HH:mm",
            "MM/dd/yyyy HH:mm:ss"
    };

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
        return parseAndSave(new BufferedReader(new StringReader(csv)), sourceName);
    }

    /**
     * Core CSV row loop: reads rows, skips the header and malformed lines, persists the rest.
     */
    public List<LogEntry> parseAndSave(BufferedReader reader, String sourceName) throws IOException {
        List<LogEntry> entries = new ArrayList<>();
        int rejected = 0;
        int withoutTimestamp = 0;

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
            if (values.length < 5) {
                rejected++;
                log.warn("{}: skipped malformed row: {}", sourceName, line);
                continue;
            }

            LocalDateTime eventTime = parseTimestamp(values[0].trim());
            if (eventTime == null) {
                // Never fabricate an event time - an unknown timestamp stays unknown so the
                // entry is excluded from time-windowed rules instead of being mis-placed.
                withoutTimestamp++;
                log.warn("{}: unreadable timestamp, stored without event time: {}", sourceName, values[0].trim());
            }

            entries.add(LogEntry.builder()
                    .eventTime(eventTime)
                    .sourceIp(values[1].trim())
                    .commandType(values[2].trim())
                    .status(values[3].trim())
                    .deviceId(values[4].trim())
                    .rawLine(line)
                    .build());
        }

        List<LogEntry> saved = logEntryRepository.saveAll(entries);
        log.info("Parsed {}: {} rows stored, {} malformed rows skipped, {} without usable timestamp",
                sourceName, saved.size(), rejected, withoutTimestamp);
        return saved;
    }

    /**
     * Detects the CSV header row.
     *
     * <p>The check is deliberately strict: a loose "contains" test used to swallow real
     * data rows whose text happened to include a header word (e.g. a device called
     * "SOURCEIP-GATEWAY"), which silently lost evidence. A header is only accepted
     * when the first column is literally named "timestamp" (or the row lists all
     * known column names).</p>
     */
    private boolean isHeader(String line) {
        String[] values = line.split(",", -1);
        if (values.length < 5) {
            return false;
        }
        String first = values[0].trim().toLowerCase();
        if (List.of("timestamp", "datetime", "date_time", "ts", "time").contains(first)) {
            return true;
        }
        List<String> known = List.of("timestamp", "sourceip", "command", "status", "deviceid");
        for (int i = 0; i < 5; i++) {
            if (!known.contains(values[i].trim().toLowerCase())) {
                return false;
            }
        }
        return true;
    }

    /**
     * @return the parsed timestamp, or {@code null} when the value cannot be interpreted
     */
    private LocalDateTime parseTimestamp(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        for (String pattern : TIMESTAMP_PATTERNS) {
            try {
                return LocalDateTime.parse(raw, DateTimeFormatter.ofPattern(pattern));
            } catch (Exception ignored) {
                // try next pattern
            }
        }
        return null;
    }
}
