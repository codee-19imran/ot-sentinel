package com.ot.sentinel.repository;

import java.time.LocalDateTime;

/**
 * Lightweight projection used by the rule engine - only the three columns the
 * detection rules actually need, instead of full entities.
 */
public interface LogRow {

    String getSourceIp();

    String getCommandType();

    LocalDateTime getEventTime();
}
