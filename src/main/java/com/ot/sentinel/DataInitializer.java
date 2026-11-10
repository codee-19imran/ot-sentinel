package com.ot.sentinel;

import com.ot.sentinel.model.User;
import com.ot.sentinel.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Seeds default local accounts so the dashboard is usable immediately after first build.
 * Defaults: admin / admin123  and  engineer / engineer123
 *
 * <p>The passwords can be overridden via {@code ot-sentinel.demo.*} properties.
 * Existing accounts are never overwritten, so changing a password on a running
 * installation is not undone by a restart.</p>
 */
@Configuration
public class DataInitializer {

    private static final Logger log = LoggerFactory.getLogger(DataInitializer.class);

    @Value("${ot-sentinel.demo.admin-password:admin123}")
    private String adminPassword;

    @Value("${ot-sentinel.demo.engineer-password:engineer123}")
    private String engineerPassword;

    @Bean
    CommandLineRunner initUsers(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        return args -> {
            boolean seeded = false;
            if (userRepository.findByUsername("admin").isEmpty()) {
                userRepository.save(User.builder()
                        .username("admin")
                        .password(passwordEncoder.encode(adminPassword))
                        .role("ADMIN")
                        .build());
                seeded = true;
            }
            if (userRepository.findByUsername("engineer").isEmpty()) {
                userRepository.save(User.builder()
                        .username("engineer")
                        .password(passwordEncoder.encode(engineerPassword))
                        .role("ENGINEER")
                        .build());
                seeded = true;
            }
            if (seeded) {
                log.warn("Seeded default accounts 'admin' and 'engineer' with the built-in demo passwords. "
                        + "Change them (ot-sentinel.demo.*) before using OT-Sentinel on a real network.");
            }
        };
    }
}
