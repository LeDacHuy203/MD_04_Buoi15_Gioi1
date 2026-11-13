package com.example.identityservice;

import com.example.identityservice.config.JwtUtil;
import com.example.identityservice.entity.User;
import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

class JwtUtilTest {

    private JwtUtil jwtUtil;

    @BeforeEach
    void setUp() {
        jwtUtil = new JwtUtil();
        ReflectionTestUtils.setField(jwtUtil, "secret", "thien-tay-nhan-809671-363636-676767-identity-service-secret-key-hs256");
        ReflectionTestUtils.setField(jwtUtil, "accessTokenExpiration", 900000L); // 15 phút
    }

    @Test
    @DisplayName("Kiểm tra Access Token chứa đầy đủ các Claim: sub, role, jti và thời hạn 15 phút")
    void testGenerateAccessToken_ContainsRequiredClaims() {
        User user = User.builder()
                .username("student1")
                .role("STUDENT")
                .build();

        long beforeGen = System.currentTimeMillis();
        String token = jwtUtil.generateAccessToken(user);
        long afterGen = System.currentTimeMillis();

        assertNotNull(token);
        assertTrue(jwtUtil.validateToken(token));

        Claims claims = jwtUtil.extractAllClaims(token);

        // Kiểm tra Standard Claim 'sub'
        assertEquals("student1", claims.getSubject());
        assertEquals("student1", jwtUtil.extractUsername(token));

        // Kiểm tra Private Claim 'role'
        assertEquals("STUDENT", claims.get("role", String.class));
        assertEquals("STUDENT", jwtUtil.extractRole(token));

        // Bắt buộc có claim 'jti' (JWT ID)
        assertNotNull(claims.getId(), "Claim jti không được null");
        assertFalse(claims.getId().isBlank(), "Claim jti không được rỗng");
        assertEquals(claims.getId(), jwtUtil.extractJti(token));

        // Kiểm tra thời gian hết hạn (15 phút = 900s)
        Date expiration = claims.getExpiration();
        assertNotNull(expiration);
        long diffMs = expiration.getTime() - beforeGen;
        assertTrue(diffMs >= 899000 && diffMs <= 901000, "Thời gian sống của token phải là 15 phút");
    }
}
