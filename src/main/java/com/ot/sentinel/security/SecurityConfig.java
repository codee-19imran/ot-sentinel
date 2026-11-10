package com.ot.sentinel.security;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;

/**
 * Spring Security configuration for OT-Sentinel.
 * - Stateless session (JWT carried in HttpOnly cookie).
 * - Login/logout and static resources are public; everything else requires authentication.
 * - The H2 console is opt-in and, when enabled, still requires an authenticated session.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    /** Paths that never require a session. */
    private static final String[] PUBLIC_PATHS = {
            "/", "/login", "/api/auth/login", "/api/auth/logout",
            "/css/**", "/js/**", "/lib/**", "/images/**",
            "/error"
    };

    /** The embedded DB console is disabled by default - see application.properties. */
    @Value("${ot-sentinel.h2-console.enabled:false}")
    private boolean h2ConsoleEnabled;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http,
                                           JwtAuthenticationFilter jwtAuthFilter) throws Exception {
        http
                // The session is stateless and authenticated by a JWT cookie. CSRF tokens are
                // not used; the auth cookie is issued with SameSite=Lax so that cross-site
                // POSTs cannot ride on the session (see AuthController).
                .csrf(csrf -> csrf.disable())
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> {
                    auth.requestMatchers(PUBLIC_PATHS).permitAll();
                    if (h2ConsoleEnabled) {
                        // Even when switched on, the console needs a valid session.
                        auth.requestMatchers("/h2-console/**").authenticated();
                    }
                    auth.anyRequest().authenticated();
                })
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling(eh -> eh
                        // API clients get a JSON 401 (so the frontend can handle it),
                        // browsers are redirected to the login page.
                        .authenticationEntryPoint((req, res, ex) -> {
                            if (req.getRequestURI().startsWith("/api/")) {
                                writeUnauthorized(res);
                            } else {
                                res.sendRedirect("/login");
                            }
                        }))
                .headers(headers -> headers
                        .frameOptions(frame -> frame.sameOrigin())
                );
        return http.build();
    }

    private static void writeUnauthorized(HttpServletResponse res) throws IOException {
        res.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        res.setContentType("application/json;charset=UTF-8");
        res.getWriter().write("{\"error\":\"unauthorized\",\"message\":\"Session expired - please sign in again.\"}");
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
