package com.ot.sentinel.repository;

import com.ot.sentinel.model.Incident;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

/**
 * Repository for detected forensic incidents.
 */
public interface IncidentRepository extends JpaRepository<Incident, Long> {

    List<Incident> findByResolvedFalse();

    List<Incident> findBySeverity(String severity);

    long countBySeverity(String severity);

    /** Severity -> number of occurrences, aggregated in the database. */
    @Query("select i.severity as label, count(i) as total from Incident i "
            + "where i.severity is not null group by i.severity")
    List<LabelCount> countBySeverityGrouped();
}
