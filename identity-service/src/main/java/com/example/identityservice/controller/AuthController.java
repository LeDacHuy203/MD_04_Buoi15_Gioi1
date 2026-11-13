package com.example.identityservice.controller;

import com.example.identityservice.dto.request.LoginRequest;
import com.example.identityservice.dto.request.RefreshTokenRequest;
import com.example.identityservice.dto.request.RegisterRequest;
import com.example.identityservice.dto.response.ApiResponse;
import com.example.identityservice.dto.response.AuthResponse;
import com.example.identityservice.entity.User;
import com.example.identityservice.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    /**
     * API Đăng nhập cấp phát Access Token & Refresh Token
     * POST /api/auth/login
     */
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        AuthResponse response = authService.login(request);
        return ResponseEntity.ok(response);
    }

    /**
     * API Đăng ký tài khoản mới (hỗ trợ tạo nhanh user test)
     * POST /api/auth/register
     */
    @PostMapping("/register")
    public ResponseEntity<ApiResponse<User>> register(@Valid @RequestBody RegisterRequest request) {
        User createdUser = authService.register(request);
        // Ẩn mật khẩu khi phản hồi
        createdUser.setPassword("******");
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.success(createdUser, "Đăng ký tài khoản thành công!"));
    }

    /**
     * API Cấp lại Access Token mới khi hết hạn sử dụng Refresh Token
     * POST /api/auth/refresh
     */
    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(@Valid @RequestBody RefreshTokenRequest request) {
        AuthResponse response = authService.refreshAccessToken(request);
        return ResponseEntity.ok(response);
    }
}
