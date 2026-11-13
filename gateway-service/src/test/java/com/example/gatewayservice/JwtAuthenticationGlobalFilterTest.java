package com.example.gatewayservice;

import com.example.gatewayservice.filter.JwtAuthenticationGlobalFilter;
import com.example.gatewayservice.util.JwtUtil;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class JwtAuthenticationGlobalFilterTest {

    private final String SECRET = "thien-tay-nhan-809671-363636-676767-identity-service-secret-key-hs256";

    @Spy
    private JwtUtil jwtUtil = new JwtUtil();

    @Mock
    private GatewayFilterChain chain;

    @InjectMocks
    private JwtAuthenticationGlobalFilter filter;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(jwtUtil, "secret", SECRET);
    }

    private String createToken(String username, String role, long expirationMs, String secretKey) {
        return Jwts.builder()
                .setId(UUID.randomUUID().toString())
                .setSubject(username)
                .claim("role", role)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expirationMs))
                .signWith(Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8)), SignatureAlgorithm.HS256)
                .compact();
    }

    @Test
    @DisplayName("Chặn ngay lập tức khi không đính kèm Authorization header (401 Unauthorized)")
    void testMissingAuthorizationHeader_Returns401() {
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/courses").build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        filter.filter(exchange, chain).block();

        assertEquals(HttpStatus.UNAUTHORIZED, exchange.getResponse().getStatusCode());
        verify(chain, never()).filter(any());
    }

    @Test
    @DisplayName("Chặn ngay lập tức khi token hết hạn (401 Unauthorized)")
    void testExpiredToken_Returns401() {
        // Token đã hết hạn từ 5 giây trước
        String expiredToken = createToken("student1", "STUDENT", -5000L, SECRET);

        MockServerHttpRequest request = MockServerHttpRequest.get("/api/courses")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + expiredToken)
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        filter.filter(exchange, chain).block();

        assertEquals(HttpStatus.UNAUTHORIZED, exchange.getResponse().getStatusCode());
        verify(chain, never()).filter(any());
    }

    @Test
    @DisplayName("Chặn ngay lập tức khi token sai chữ ký (401 Unauthorized)")
    void testInvalidSignature_Returns401() {
        // Token ký bởi secret key khác
        String invalidToken = createToken("student1", "STUDENT", 60000L, "wrong-secret-key-that-does-not-match-at-all-12345");

        MockServerHttpRequest request = MockServerHttpRequest.get("/api/courses")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + invalidToken)
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        filter.filter(exchange, chain).block();

        assertEquals(HttpStatus.UNAUTHORIZED, exchange.getResponse().getStatusCode());
        verify(chain, never()).filter(any());
    }

    @Test
    @DisplayName("Token hợp lệ: trích xuất role và gắn vào Header X-User-Role trước khi forward")
    void testValidToken_AppendsXUserRoleHeader() {
        String validToken = createToken("student1", "STUDENT", 900000L, SECRET);

        MockServerHttpRequest request = MockServerHttpRequest.get("/api/courses")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + validToken)
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        when(chain.filter(any(ServerWebExchange.class))).thenReturn(Mono.empty());

        filter.filter(exchange, chain).block();

        ArgumentCaptor<ServerWebExchange> captor = ArgumentCaptor.forClass(ServerWebExchange.class);
        verify(chain).filter(captor.capture());

        ServerWebExchange capturedExchange = captor.getValue();
        String passedRole = capturedExchange.getRequest().getHeaders().getFirst("X-User-Role");
        String passedUser = capturedExchange.getRequest().getHeaders().getFirst("X-User-Name");

        assertEquals("STUDENT", passedRole);
        assertEquals("student1", passedUser);
    }
}
