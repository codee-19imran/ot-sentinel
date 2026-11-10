package com.ot.sentinel.repository;

/**
 * Projection for grouped counts produced by the aggregation queries
 * (e.g. {@code select l.status as label, count(l) as total ...}).
 */
public interface LabelCount {

    String getLabel();

    long getTotal();
}
