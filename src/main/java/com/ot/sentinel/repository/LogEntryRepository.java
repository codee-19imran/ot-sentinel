package com.ot.sentinel.repository;

import com.ot.sentinel.model.LogEntry;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Repository for parsed OT log entries.
 */
public interface LogEntryRepository extends JpaRepository<LogEntry, Long> {

    List<LogEntry> findByStatus(String status);

    long countByStatus(String status);

    List<LogEntry> findBySourceIp(String sourceIp);
}
