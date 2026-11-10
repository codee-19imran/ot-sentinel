package com.ot.sentinel.repository;

import com.ot.sentinel.model.LogEntry;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Repository for parsed OT log entries.
 *
 * <p>All reporting queries aggregate in the database (GROUP BY) or return
 * narrow projections, so the dashboard never pulls the whole log table into
 * memory. This keeps page loads fast on large forensic datasets.</p>
 */
public interface LogEntryRepository extends JpaRepository<LogEntry, Long> {

    List<LogEntry> findByStatus(String status);

    long countByStatus(String status);

    List<LogEntry> findBySourceIp(String sourceIp);

    /** Newest entries first - powers the "Recent Log Entries" table. */
    List<LogEntry> findTop20ByOrderByEventTimeDesc();

    /** Command type -> number of occurrences. */
    @Query("select l.commandType as label, count(l) as total from LogEntry l "
            + "where l.commandType is not null group by l.commandType order by count(l) desc")
    List<LabelCount> countByCommand();

    /** Status -> number of occurrences. */
    @Query("select l.status as label, count(l) as total from LogEntry l "
            + "where l.status is not null group by l.status")
    List<LabelCount> countByStatusGrouped();

    /** Source IP -> number of occurrences; pass a Pageable to limit the result. */
    @Query("select l.sourceIp as label, count(l) as total from LogEntry l "
            + "where l.sourceIp is not null group by l.sourceIp order by count(l) desc")
    List<LabelCount> countBySourceIp(Pageable pageable);

    /** Only the event times inside the given window - single column projection. */
    @Query("select l.eventTime from LogEntry l where l.eventTime between :from and :to")
    List<LocalDateTime> findEventTimesBetween(@Param("from") LocalDateTime from, @Param("to") LocalDateTime to);

    /** Compact projection (source, command, time) consumed by the rule engine. */
    @Query("select l.sourceIp as sourceIp, l.commandType as commandType, l.eventTime as eventTime "
            + "from LogEntry l")
    List<LogRow> findAllForAnalysis();

    /**
     * Failed operations per source IP since a point in time.
     * Drives the brute-force rule without loading the log table into memory.
     */
    @Query("select l.sourceIp as label, count(l) as total from LogEntry l "
            + "where l.status = 'FAILURE' and l.eventTime is not null and l.eventTime >= :since "
            + "and l.sourceIp is not null group by l.sourceIp order by count(l) desc")
    List<LabelCount> countFailuresPerIpSince(@Param("since") LocalDateTime since);

    /** Entries whose command is one of the given control commands (source + command only). */
    @Query("select l.sourceIp as sourceIp, l.commandType as commandType from LogEntry l "
            + "where l.commandType in :commands and l.sourceIp is not null")
    List<LogRow> findByCommandTypes(@Param("commands") List<String> commands);

    /** Source IP + event time only - used by the off-hours rule. */
    @Query("select l.sourceIp as sourceIp, l.eventTime as eventTime from LogEntry l "
            + "where l.eventTime is not null and l.sourceIp is not null")
    List<LogRow> findSourceAndEventTimes();
}
