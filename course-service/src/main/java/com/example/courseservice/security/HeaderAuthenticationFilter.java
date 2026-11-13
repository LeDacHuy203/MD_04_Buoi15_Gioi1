package com.example.courseservice.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@Slf4j
@Component
public class HeaderAuthenticationFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // 1. Đọc quyền trực tiếp từ Header X-User-Role do Gateway truyền xuống
        String role = request.getHeader("X-User-Role");
        String username = request.getHeader("X-User-Name");

        if (username == null || username.isBlank()) {
            username = "anonymousUser";
        }

        if (role != null && !role.isBlank()) {
            log.info("--> [Course-Service] Nhận Header X-User-Role: {}, X-User-Name: {}", role, username);

            List<GrantedAuthority> authorities = new ArrayList<>();
            // Authority tương ứng trực tiếp với hasAuthority('STUDENT'), hasAuthority('INSTRUCTOR')
            authorities.add(new SimpleGrantedAuthority(role));

            // Đặt Authentication vào SecurityContextHolder
            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(username, null, authorities);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        } else {
            // Không có Header X-User-Role -> xóa context hoặc để unauthenticated
            SecurityContextHolder.clearContext();
        }

        filterChain.doFilter(request, response);
    }
}
