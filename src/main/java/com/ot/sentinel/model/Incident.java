package com.ot.sentinel.model;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;

/**
 * A detected security incident produced by the rule engine.
 */
@Entity
@Table(name = "incidents")
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

    private LocalDateTime detectedAt;

    private boolean resolved;
}
