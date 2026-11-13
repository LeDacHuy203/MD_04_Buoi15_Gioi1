package com.example.identityservice;

import com.example.identityservice.config.JwtUtil;
import com.example.identityservice.dto.request.LoginRequest;
import com.example.identityservice.dto.response.AuthResponse;
import com.example.identityservice.entity.RefreshToken;
import com.example.identityservice.entity.User;
import com.example.identityservice.repository.RefreshTokenRepository;
import com.example.identityservice.repository.UserRepository;
import com.example.identityservice.service.AuthService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtUtil jwtUtil;

    @InjectMocks
    private AuthService authService;

    private User sampleUser;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(authService, "accessTokenExpirationMs", 900000L);

        sampleUser = User.builder()
                .id("user-uuid-123")
                .username("student1")
                .password("$2a$10$hashedPasswordSample")
                .role("STUDENT")
                .build();
    }

    @Test
    @DisplayName("Đăng nhập thành công trả về cả Access Token và Refresh Token, lưu Refresh Token vào DB")
    void testLogin_Success() {
        LoginRequest request = new LoginRequest("student1", "123456");

        when(userRepository.findByUsername("student1")).thenReturn(Optional.of(sampleUser));
        when(passwordEncoder.matches("123456", sampleUser.getPassword())).thenReturn(true);
        when(jwtUtil.generateAccessToken(sampleUser)).thenReturn("mock.jwt.access.token");
        when(refreshTokenRepository.save(any(RefreshToken.class))).thenAnswer(invocation -> invocation.getArgument(0));

        AuthResponse response = authService.login(request);

        assertNotNull(response);
        assertEquals("mock.jwt.access.token", response.getAccessToken());
        assertNotNull(response.getRefreshToken());
        assertEquals("Bearer", response.getTokenType());
        assertEquals(900L, response.getExpiresIn());
        assertEquals("student1", response.getUsername());
        assertEquals("STUDENT", response.getRole());

        // Xác minh refresh token được lưu vào DB với hạn dùng xấp xỉ 7 ngày
        ArgumentCaptor<RefreshToken> captor = ArgumentCaptor.forClass(RefreshToken.class);
        verify(refreshTokenRepository).save(captor.capture());
        RefreshToken savedToken = captor.getValue();
        assertEquals(sampleUser, savedToken.getUser());
        assertNotNull(savedToken.getToken());
        assertTrue(savedToken.getExpiryDate().isAfter(Instant.now().plus(6, ChronoUnit.DAYS)));
    }

    @Test
    @DisplayName("Đăng nhập thất bại khi sai mật khẩu sẽ ném BadCredentialsException")
    void testLogin_WrongPassword_ThrowsException() {
        LoginRequest request = new LoginRequest("student1", "wrongpassword");

        when(userRepository.findByUsername("student1")).thenReturn(Optional.of(sampleUser));
        when(passwordEncoder.matches("wrongpassword", sampleUser.getPassword())).thenReturn(false);

        assertThrows(BadCredentialsException.class, () -> authService.login(request));
        verify(refreshTokenRepository, never()).save(any());
    }

    @Test
    @DisplayName("Đăng nhập thất bại khi không tìm thấy username sẽ ném BadCredentialsException")
    void testLogin_UserNotFound_ThrowsException() {
        LoginRequest request = new LoginRequest("unknown_user", "123456");

        when(userRepository.findByUsername("unknown_user")).thenReturn(Optional.empty());

        assertThrows(BadCredentialsException.class, () -> authService.login(request));
        verify(refreshTokenRepository, never()).save(any());
    }
}
