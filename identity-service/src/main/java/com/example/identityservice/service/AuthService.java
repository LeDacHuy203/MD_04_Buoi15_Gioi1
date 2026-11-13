package com.example.identityservice.service;

import com.example.identityservice.config.JwtUtil;
import com.example.identityservice.dto.request.LoginRequest;
import com.example.identityservice.dto.request.RefreshTokenRequest;
import com.example.identityservice.dto.request.RegisterRequest;
import com.example.identityservice.dto.response.AuthResponse;
import com.example.identityservice.entity.RefreshToken;
import com.example.identityservice.entity.User;
import com.example.identityservice.repository.RefreshTokenRepository;
import com.example.identityservice.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    @Value("${jwt.access-token-expiration:900000}")
    private long accessTokenExpirationMs;

    /**
     * Xử lý đăng nhập:
     * 1. So khớp mật khẩu với chuỗi BCrypt trong DB
     * 2. Nếu đúng: cấp Access Token (HS256, 15 phút, sub, role, jti)
     * 3. Cấp Refresh Token (chuỗi ngẫu nhiên, sống 7 ngày) và lưu vào bảng refresh_tokens
     * 4. Trả về cả cặp Access Token và Refresh Token
     */
    @Transactional
    public AuthResponse login(LoginRequest request) {
        // 1. Tìm user trong DB theo username
        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new BadCredentialsException("Tên đăng nhập hoặc mật khẩu không chính xác"));

        // 2. So khớp mật khẩu gửi lên với mật khẩu băm BCrypt trong DB
        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new BadCredentialsException("Tên đăng nhập hoặc mật khẩu không chính xác");
        }

        // 3. Sinh Access Token (HS256, sống 15 phút, chứa sub, role, jti)
        String accessToken = jwtUtil.generateAccessToken(user);

        // 4. Sinh Refresh Token ngẫu nhiên, hạn dùng 7 ngày và lưu vào DB
        RefreshToken refreshToken = RefreshToken.builder()
                .token(UUID.randomUUID().toString())
                .expiryDate(Instant.now().plus(7, ChronoUnit.DAYS))
                .user(user)
                .build();
        refreshToken = refreshTokenRepository.save(refreshToken);

        // 5. Trả về client cả cặp Access và Refresh Token
        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken.getToken())
                .tokenType("Bearer")
                .expiresIn(accessTokenExpirationMs / 1000) // ví dụ 900 giây
                .username(user.getUsername())
                .role(user.getRole())
                .build();
    }

    /**
     * Đăng ký tài khoản người dùng mới
     */
    @Transactional
    public User register(RegisterRequest request) {
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new IllegalArgumentException("Username '" + request.getUsername() + "' đã tồn tại!");
        }

        User user = User.builder()
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(request.getRole() != null && !request.getRole().isBlank() ? request.getRole() : "STUDENT")
                .build();

        return userRepository.save(user);
    }

    /**
     * Làm mới Access Token bằng Refresh Token hợp lệ
     */
    @Transactional(readOnly = true)
    public AuthResponse refreshAccessToken(RefreshTokenRequest request) {
        RefreshToken refreshToken = refreshTokenRepository.findByToken(request.getRefreshToken())
                .orElseThrow(() -> new IllegalArgumentException("Refresh Token không tồn tại hoặc không hợp lệ!"));

        if (refreshToken.getExpiryDate().isBefore(Instant.now())) {
            throw new IllegalArgumentException("Refresh Token đã hết hạn! Vui lòng đăng nhập lại.");
        }

        User user = refreshToken.getUser();
        String newAccessToken = jwtUtil.generateAccessToken(user);

        return AuthResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(refreshToken.getToken())
                .tokenType("Bearer")
                .expiresIn(accessTokenExpirationMs / 1000)
                .username(user.getUsername())
                .role(user.getRole())
                .build();
    }
}
