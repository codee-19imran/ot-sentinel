package com.ot.sentinel.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for JWT token issuance and validation.
 */
class JwtUtilTest {

    private JwtUtil jwtUtil;

    @BeforeEach
    void setUp() {
        jwtUtil = new JwtUtil();
        ReflectionTestUtils.setField(jwtUtil, "secret",
                "test-secret-key-that-is-long-enough-for-hs256-0123456789");
        ReflectionTestUtils.setField(jwtUtil, "expiration", 3600_000L);
        jwtUtil.init();
    }

    @Test
    void issuesAndValidatesToken() {
        String token = jwtUtil.generateToken("admin");

        assertThat(token).isNotBlank().startsWith("ey");
        assertThat(jwtUtil.validateToken(token)).isTrue();
        assertThat(jwtUtil.extractUsername(token)).isEqualTo("admin");
    }

    @Test
    void detectsExpiredToken() {
        ReflectionTestUtils.setField(jwtUtil, "expiration", -1000L);
        jwtUtil.init(); // re-initialise with negative TTL so the token is already expired

        String token = jwtUtil.generateToken("admin");
        assertThat(jwtUtil.validateToken(token)).isFalse();
    }

    @Test
    void rejectsTamperedSignature() {
        String token = jwtUtil.generateToken("admin");
        String tampered = token.substring(0, token.length() - 3) + "xxx";
        assertThat(jwtUtil.validateToken(tampered)).isFalse();
    }

    @Test
    void tokensBoundToTheirOwnSecret() {
        String token = jwtUtil.generateToken("engineer");
        assertThat(jwtUtil.validateToken(token)).isTrue();
        assertThat(jwtUtil.extractUsername(token)).isEqualTo("engineer");
    }
}
