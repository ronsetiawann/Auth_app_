package com.strade.auth_app.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.strade.auth_app.dto.response.ApiResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Access denied handler
 * Handles forbidden access attempts
 */
@Component
@Slf4j
@RequiredArgsConstructor
public class JwtAccessDeniedHandler implements AccessDeniedHandler {

    private final ObjectMapper objectMapper;

    @Override
    public void handle(
            HttpServletRequest request,
            HttpServletResponse response,
            AccessDeniedException accessDeniedException
    ) throws IOException {

        log.warn("Access denied: {} {} - {}",
                request.getMethod(),
                request.getRequestURI(),
                accessDeniedException.getMessage());

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);

        ApiResponse<Void> apiResponse = ApiResponse.error(
                ApiResponse.ApiError.builder()
                        .code(HttpServletResponse.SC_FORBIDDEN)
                        .message("Access denied")
                        .details(accessDeniedException.getMessage())
                        .build()
        );

        objectMapper.writeValue(response.getOutputStream(), apiResponse);
    }
}
