package com.example.gatewayservice.filter;

import com.example.gatewayservice.util.JwtUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationGlobalFilter implements GlobalFilter, Ordered {

    private final JwtUtil jwtUtil;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();

        // 1. Chỉ chặn và kiểm tra các request định tuyến tới /api/courses/**
        if (!path.startsWith("/api/courses")) {
            return chain.filter(exchange);
        }

        log.info("--> [Gateway Trạm gác biên phòng] Đang kiểm tra JWT cho request: {}", path);

        // 2. Lấy Header Authorization
        List<String> authHeaders = request.getHeaders().get(HttpHeaders.AUTHORIZATION);
        if (authHeaders == null || authHeaders.isEmpty()) {
            log.warn("--> [Gateway Chặn] Không tìm thấy Header Authorization");
            return onError(exchange, "Thiếu Header Authorization. Vui lòng đính kèm Bearer Token!", HttpStatus.UNAUTHORIZED);
        }

        String authHeader = authHeaders.get(0);
        if (!authHeader.startsWith("Bearer ")) {
            log.warn("--> [Gateway Chặn] Header Authorization không đúng định dạng 'Bearer '");
            return onError(exchange, "Header Authorization phải bắt đầu bằng 'Bearer '!", HttpStatus.UNAUTHORIZED);
        }

        String token = authHeader.substring(7).trim();

        // 3. Giải mã JWT bằng Secret Key dùng chung với Identity Service
        try {
            Claims claims = jwtUtil.extractAllClaims(token);

            // 4. Trích xuất role từ Payload
            String role = claims.get("role", String.class);
            if (role == null) {
                role = "UNKNOWN";
            }
            String username = claims.getSubject() != null ? claims.getSubject() : "";

            log.info("--> [Gateway Cho qua] Token hợp lệ! User: {}, Role: {}", username, role);

            // 5. Gắn role vào một Header mới tên là X-User-Role trước khi forward request xuống Course-Service
            ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                    .header("X-User-Role", role)
                    .header("X-User-Name", username)
                    .build();

            return chain.filter(exchange.mutate().request(mutatedRequest).build());

        } catch (ExpiredJwtException e) {
            log.warn("--> [Gateway Chặn] Token đã hết hạn: {}", e.getMessage());
            return onError(exchange, "Token đã hết hạn (Expired JWT)! Vui lòng đăng nhập lại để nhận token mới.", HttpStatus.UNAUTHORIZED);
        } catch (SignatureException e) {
            log.warn("--> [Gateway Chặn] Sai chữ ký Token: {}", e.getMessage());
            return onError(exchange, "Chữ ký Token không hợp lệ (SignatureException)!", HttpStatus.UNAUTHORIZED);
        } catch (MalformedJwtException | UnsupportedJwtException | IllegalArgumentException e) {
            log.warn("--> [Gateway Chặn] Token không đúng định dạng: {}", e.getMessage());
            return onError(exchange, "Token JWT không đúng định dạng hoặc bị chỉnh sửa!", HttpStatus.UNAUTHORIZED);
        } catch (Exception e) {
            log.error("--> [Gateway Chặn] Lỗi xác thực token: {}", e.getMessage());
            return onError(exchange, "Lỗi xác thực Token: " + e.getMessage(), HttpStatus.UNAUTHORIZED);
        }
    }

    /**
     * Trả về phản hồi lỗi 401 Unauthorized dưới dạng JSON chuẩn
     */
    private Mono<Void> onError(ServerWebExchange exchange, String message, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        String jsonResponse = String.format(
                "{\"status\":%d,\"error\":\"%s\",\"message\":\"%s\"}",
                httpStatus.value(),
                httpStatus.getReasonPhrase(),
                message
        );

        byte[] bytes = jsonResponse.getBytes(StandardCharsets.UTF_8);
        DataBuffer buffer = response.bufferFactory().wrap(bytes);
        return response.writeWith(Mono.just(buffer));
    }

    @Override
    public int getOrder() {
        // Thứ tự ưu tiên cao nhất để chạy trước các filter định tuyến
        return -1;
    }
}
