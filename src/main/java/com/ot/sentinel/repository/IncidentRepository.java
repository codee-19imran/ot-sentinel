package com.ot.sentinel.repository;

import com.ot.sentinel.model.Incident;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

/**
 * Repository for detected forensic incidents.
 */
public interface IncidentRepository extends JpaRepository<Incident, Long> {

    List<Incident> findByResolvedFalse();

    List<Incident> findBySeverity(String severity);

    long countBySeverity(String severity);
}
