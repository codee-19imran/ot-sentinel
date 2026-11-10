package com.ot.sentinel.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Tracks failed sign-in attempts per account and locks the account temporarily
 * once the threshold is exceeded.
 *
 * <p>OT-Sentinel is used to hunt brute-force attacks, so its own sign-in must
 * not be brute-forceable. State is kept in memory only - a restart clears it,
 * which is acceptable for a local, air-gapped installation.</p>
 */
@Service
public class LoginAttemptService {

    private static final Logger log = LoggerFactory.getLogger(LoginAttemptService.class);

    private final int maxAttempts;
    private final long lockoutMinutes;

    private final Map<String, Attempt> attempts = new ConcurrentHashMap<>();

    public LoginAttemptService(@Value("${ot-sentinel.security.max-login-attempts:5}") int maxAttempts,
                                @Value("${ot-sentinel.security.login-lockout-minutes:5}") long lockoutMinutes) {
        this.maxAttempts = maxAttempts;
        this.lockoutMinutes = lockoutMinutes;
    }

    /** @return true when the account is currently locked out */
    public boolean isLocked(String key) {
        Attempt attempt = attempts.get(key);
        if (attempt == null) {
            return false;
        }
        if (attempt.lockedUntil != null && attempt.lockedUntil.isAfter(Instant.now())) {
            return true;
        }
        if (attempt.lockedUntil != null) {
            // lockout expired - forget the attempt
            attempts.remove(key);
        }
        return false;
    }

    /** @return remaining lockout seconds, or 0 when the account is not locked */
    public long remainingLockSeconds(String key) {
        Attempt attempt = attempts.get(key);
        if (attempt == null || attempt.lockedUntil == null) {
            return 0;
        }
        long seconds = Duration.between(Instant.now(), attempt.lockedUntil).getSeconds();
        return Math.max(seconds, 0);
    }

    public void recordFailure(String key) {
        Attempt attempt = attempts.computeIfAbsent(key, k -> new Attempt());
        attempt.failures++;
        attempt.lastFailure = Instant.now();
        if (attempt.failures >= maxAttempts) {
            attempt.lockedUntil = Instant.now().plusSeconds(lockoutMinutes * 60);
            attempt.failures = 0;
            log.warn("Sign-in locked for {} after {} failed attempts ({} minutes)",
                    key, maxAttempts, lockoutMinutes);
        }
    }

    public void recordSuccess(String key) {
        attempts.remove(key);
    }

    /** Drops stale entries so the map cannot grow without bound. */
    public void purgeStale() {
        Instant cutoff = Instant.now().minusSeconds(lockoutMinutes * 60 * 2);
        attempts.entrySet().removeIf(e -> e.getValue().lastFailure != null
                && e.getValue().lastFailure.isBefore(cutoff));
    }

    private static final class Attempt {
        private int failures;
        private Instant lastFailure;
        private Instant lockedUntil;
    }
}
