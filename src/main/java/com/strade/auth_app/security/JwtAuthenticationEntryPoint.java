package com.strade.auth_app.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.strade.auth_app.dto.response.ApiResponse;
import com.strade.auth_app.exception.ErrorCode;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Authentication entry point
 * Handles unauthorized access attempts
 */
@Component
@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper objectMapper;

    @Override
    public void commence(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException authException
    ) throws IOException {

        log.warn("Unauthorized access attempt: {} {}",
                request.getMethod(), request.getRequestURI());

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

        ApiResponse<Void> apiResponse = ApiResponse.error(
                ApiResponse.ApiError.builder()
                        .code(ErrorCode.AUTHENTICATION_FAILED.getCode())
                        .message("Authentication required")
                        .details(authException.getMessage())
                        .build()
        );

        objectMapper.writeValue(response.getOutputStream(), apiResponse);
    }
}
