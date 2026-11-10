package com.ot.sentinel.service;

import com.ot.sentinel.model.LogEntry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Data-normalisation layer for proprietary PLC/RTU text logs.
 *
 * Many PLCs do not export CSV - they append human-readable lines such as:
 * <pre>
 * [2026-11-10 08:05:02] WARN Device=HMI-CONTROL-03 Source=192.168.1.50 Action=LOGIN Result=FAIL
 * </pre>
 * This service converts that raw format into the canonical CSV schema
 * {@code timestamp,sourceIp,command,status,deviceId} (status vocabulary unified to
 * SUCCESS/FAILURE) so the standard {@link LogParserService} can ingest it.
 *
 * Purely stream-based: no temp files, no fixed output paths.
 */
@Service
public class RawLogNormalizerService {

    private static final Logger log = LoggerFactory.getLogger(RawLogNormalizerService.class);

    /**
     * [timestamp] LEVEL Device=<id> Source=<ip-or-host> Action=<cmd> Result=<status>
     * Tolerant of extra whitespace and IPv4 or hostnames in Source.
     */
    private static final Pattern RAW_LOG_PATTERN = Pattern.compile(
            "^\\[\\s*([^\\]]+?)\\s*\\]\\s+\\w+\\s+Device=(\\S+)\\s+Source=(\\S+)\\s+Action=(\\S+)\\s+Result=(\\S+)\\s*$");

    /** Vendor words treated as a successful operation. */
    private static final Set<String> SUCCESS_WORDS = Set.of(
            "OK", "PASS", "PASSED", "SUCCESS", "SUCCEEDED", "GRANTED", "ACCEPTED", "COMPLETE", "COMPLETED");

    /** Vendor words treated as a failed operation. */
    private static final Set<String> FAILURE_WORDS = Set.of(
            "FAIL", "FAILED", "FAILURE", "ERROR", "DENIED", "REJECT", "REJECTED", "TIMEOUT", "REFUSED");

    private final LogParserService logParserService;

    public RawLogNormalizerService(LogParserService logParserService) {
        this.logParserService = logParserService;
    }

    /**
     * Ingest an uploaded proprietary-format file: normalise it to the canonical CSV
     * schema and delegate straight into the standard parser.
     *
     * @param file uploaded raw text log (.txt/.log)
     * @return the list of persisted log entries
     * @throws IOException if the file cannot be read
     */
    public List<LogEntry> ingestRawLogs(MultipartFile file) throws IOException {
        try (BufferedReader raw = new BufferedReader(
                new InputStreamReader(file.getInputStream(), StandardCharsets.UTF_8))) {
            String csv = normalizeToCsv(raw, file.getOriginalFilename());
            return logParserService.parseAndSaveCsv(csv, file.getOriginalFilename());
        }
    }

    /**
     * Convert raw PLC text lines into canonical CSV text (with header).
     * Unrecognised lines are skipped and counted, never fatal.
     */
    public String normalizeToCsv(BufferedReader raw, String sourceName) throws IOException {
        StringBuilder csv = new StringBuilder("timestamp,sourceIp,command,status,deviceId\n");
        int accepted = 0;
        int rejected = 0;

        String line;
        while ((line = raw.readLine()) != null) {
            String trimmed = line.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            Matcher m = RAW_LOG_PATTERN.matcher(trimmed);
            if (m.matches()) {
                csv.append(m.group(1).trim()).append(',')   // timestamp
                   .append(m.group(3)).append(',')          // sourceIp
                   .append(m.group(4)).append(',')          // command
                   .append(normalizeStatus(m.group(5))).append(',') // status
                   .append(m.group(2)).append('\n');        // deviceId
                accepted++;
            } else {
                rejected++;
                log.warn("{}: skipped unrecognised raw line: {}", sourceName, trimmed);
            }
        }

        log.info("Normalised {}: {} raw line(s) converted to CSV, {} unrecognised line(s) skipped",
                sourceName, accepted, rejected);
        return csv.toString();
    }

    /**
     * Unify the vendor's status vocabulary to SUCCESS/FAILURE.
     * Unknown words are passed through upper-cased so nothing is silently lost.
     */
    public static String normalizeStatus(String rawStatus) {
        String s = rawStatus == null ? "" : rawStatus.trim().toUpperCase();
        if (SUCCESS_WORDS.contains(s)) {
            return "SUCCESS";
        }
        if (FAILURE_WORDS.contains(s)) {
            return "FAILURE";
        }
        return s;
    }
}
