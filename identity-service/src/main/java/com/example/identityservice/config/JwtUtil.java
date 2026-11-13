package com.example.identityservice.config;

import com.example.identityservice.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.UUID;

@Component
public class JwtUtil {

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.access-token-expiration:900000}")
    private long accessTokenExpiration; // 15 phút = 900,000 ms

    public SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Sinh ra Access Token bằng JJWT với:
     * - Thuật toán: HS256
     * - Thời gian sống: 15 phút
     * - Standard Claim "sub": username
     * - Private Claim "role": STUDENT, INSTRUCTOR,...
     * - Claim bắt buộc "jti": JWT ID - mã định danh duy nhất
     */
    public String generateAccessToken(User user) {
        long now = System.currentTimeMillis();
        String jti = UUID.randomUUID().toString();

        return Jwts.builder()
                .setId(jti)                             // Standard claim 'jti' (JWT ID)
                .setSubject(user.getUsername())         // Standard claim 'sub' (username)
                .claim("role", user.getRole())           // Private claim 'role'
                .setIssuedAt(new Date(now))
                .setExpiration(new Date(now + accessTokenExpiration)) // Hạn sống 15 phút
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public boolean validateToken(String token) {
        try {
            extractAllClaims(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public String extractUsername(String token) {
        return extractAllClaims(token).getSubject();
    }

    public String extractRole(String token) {
        return extractAllClaims(token).get("role", String.class);
    }

    public String extractJti(String token) {
        return extractAllClaims(token).getId();
    }
}
