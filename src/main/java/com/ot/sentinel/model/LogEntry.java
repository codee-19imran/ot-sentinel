package com.ot.sentinel.model;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;

/**
 * A single parsed OT/ICS log entry (PLC/RTU audit log row).
 *
 * <p>The event time is mapped to the column {@code log_timestamp} because
 * {@code TIMESTAMP} is a reserved word in H2/SQL and would otherwise require
 * quoting in every hand-written query.</p>
 */
@Entity
@Table(name = "log_entries", indexes = {
        @Index(name = "idx_log_entries_timestamp", columnList = "log_timestamp"),
        @Index(name = "idx_log_entries_status", columnList = "status"),
        @Index(name = "idx_log_entries_source_ip", columnList = "source_ip")
})
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class LogEntry {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "log_timestamp")
    private LocalDateTime eventTime;

    private String sourceIp;

    private String commandType; // READ, WRITE, STOP, LOGIN, ...

    private String status;      // SUCCESS / FAILURE

    private String deviceId;    // PLC/RTU identifier

    private String rawLine;     // original source line for forensic traceability
}
