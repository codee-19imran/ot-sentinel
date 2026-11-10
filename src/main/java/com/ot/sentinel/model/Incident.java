package com.ot.sentinel.model;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;

/**
 * A detected security incident produced by the rule engine.
 */
@Entity
@Table(name = "incidents", indexes = {
        @Index(name = "idx_incidents_resolved", columnList = "resolved"),
        @Index(name = "idx_incidents_severity", columnList = "severity"),
        @Index(name = "idx_incidents_detected_at", columnList = "detected_at")
})
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Incident {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String type;          // BRUTE_FORCE | UNUSUAL_COMMAND | ...

    private String severity;      // LOW | MEDIUM | HIGH | CRITICAL

    private String description;

    private String sourceIp;      // offending source IP (if applicable)

    @Column(name = "detected_at")
    private LocalDateTime detectedAt;

    private boolean resolved;
}
