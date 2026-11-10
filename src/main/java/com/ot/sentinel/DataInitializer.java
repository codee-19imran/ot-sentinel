package com.ot.sentinel;

import com.ot.sentinel.model.User;
import com.ot.sentinel.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Seeds default local accounts so the dashboard is usable immediately after first build.
 * Defaults: admin / admin123  and  engineer / engineer123
 */
@Configuration
public class DataInitializer {

    @Bean
    CommandLineRunner initUsers(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        return args -> {
            if (userRepository.findByUsername("admin").isEmpty()) {
                userRepository.save(User.builder()
                        .username("admin")
                        .password(passwordEncoder.encode("admin123"))
                        .role("ADMIN")
                        .build());
            }
            if (userRepository.findByUsername("engineer").isEmpty()) {
                userRepository.save(User.builder()
                        .username("engineer")
                        .password(passwordEncoder.encode("engineer123"))
                        .role("ENGINEER")
                        .build());
            }
        };
    }
}
