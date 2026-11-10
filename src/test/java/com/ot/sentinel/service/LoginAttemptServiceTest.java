package com.ot.sentinel.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for the sign-in lockout policy.
 */
class LoginAttemptServiceTest {

    private LoginAttemptService service;

    @BeforeEach
    void setUp() {
        service = new LoginAttemptService(3, 5);
    }

    @Test
    void startsUnlocked() {
        assertThat(service.isLocked("admin|127.0.0.1")).isFalse();
    }

    @Test
    void locksAfterTheConfiguredNumberOfFailures() {
        service.recordFailure("admin|127.0.0.1");
        service.recordFailure("admin|127.0.0.1");
        assertThat(service.isLocked("admin|127.0.0.1")).isFalse();

        service.recordFailure("admin|127.0.0.1");
        assertThat(service.isLocked("admin|127.0.0.1")).isTrue();
        assertThat(service.remainingLockSeconds("admin|127.0.0.1")).isGreaterThan(0);
    }

    @Test
    void tracksAccountsIndependently() {
        service.recordFailure("admin|127.0.0.1");
        service.recordFailure("admin|127.0.0.1");
        service.recordFailure("admin|127.0.0.1");

        assertThat(service.isLocked("admin|127.0.0.1")).isTrue();
        assertThat(service.isLocked("engineer|127.0.0.1")).isFalse();
    }

    @Test
    void successfulLoginClearsTheCounter() {
        service.recordFailure("admin|127.0.0.1");
        service.recordFailure("admin|127.0.0.1");
        service.recordSuccess("admin|127.0.0.1");

        assertThat(service.isLocked("admin|127.0.0.1")).isFalse();

        // the counter restarted
        service.recordFailure("admin|127.0.0.1");
        service.recordFailure("admin|127.0.0.1");
        assertThat(service.isLocked("admin|127.0.0.1")).isFalse();
    }

    @Test
    void purgeRemovesStaleEntries() {
        service.recordFailure("admin|127.0.0.1");
        service.purgeStale();

        // a fresh failure still locks after the threshold
        service.recordFailure("admin|127.0.0.1");
        service.recordFailure("admin|127.0.0.1");
        service.recordFailure("admin|127.0.0.1");
        assertThat(service.isLocked("admin|127.0.0.1")).isTrue();
    }
}
