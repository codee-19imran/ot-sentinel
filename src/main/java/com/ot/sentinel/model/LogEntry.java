package com.ot.sentinel.model;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;

/**
 * A single parsed OT/ICS log entry (PLC/RTU audit log row).
 */
@Entity
@Table(name = "log_entries")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class LogEntry {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "log_timestamp")
    private LocalDateTime timestamp;

    private String sourceIp;

    private String commandType; // READ, WRITE, STOP, LOGIN, ...

    private String status;      // SUCCESS / FAILURE

    private String deviceId;    // PLC/RTU identifier

    private String rawLine;     // original CSV line for forensic traceability
}
