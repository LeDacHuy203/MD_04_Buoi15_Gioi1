package com.example.identityservice.config;

import com.example.identityservice.entity.User;
import com.example.identityservice.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class DataInitializer implements CommandLineRunner {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) {
        // Seed tài khoản mẫu cho sinh viên
        if (!userRepository.existsByUsername("student1")) {
            User student = User.builder()
                    .username("student1")
                    .password(passwordEncoder.encode("123456"))
                    .role("STUDENT")
                    .build();
            userRepository.save(student);
            log.info("--> Seeded default user: student1 / 123456 (ROLE: STUDENT)");
        }

        // Seed tài khoản mẫu cho giảng viên
        if (!userRepository.existsByUsername("instructor1")) {
            User instructor = User.builder()
                    .username("instructor1")
                    .password(passwordEncoder.encode("123456"))
                    .role("INSTRUCTOR")
                    .build();
            userRepository.save(instructor);
            log.info("--> Seeded default user: instructor1 / 123456 (ROLE: INSTRUCTOR)");
        }
    }
}
