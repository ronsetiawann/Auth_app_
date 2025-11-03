package com.strade.auth_app.security.filter;

import com.strade.auth_app.constant.AppConstants;
import com.strade.auth_app.exception.TokenException;
import com.strade.auth_app.security.AuthenticationContext;
import com.strade.auth_app.security.jwt.JwtClaims;
import com.strade.auth_app.security.jwt.JwtValidator;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * JWT Authentication Filter
 * Intercepts requests and validates JWT token
 */
@Component
@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtValidator jwtValidator;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        try {
            // 1. Extract JWT token from Authorization header
            String token = extractToken(request);

            if (token == null) {
                // No token, continue without authentication
                filterChain.doFilter(request, response);
                return;
            }

            // 2. Validate and parse JWT token
            JwtClaims claims = jwtValidator.validateAndParseClaims(token);

            // 3. Create authentication context
            AuthenticationContext authContext = AuthenticationContext.fromJwtClaims(claims);
            authContext.setIpAddress(getClientIp(request));
            authContext.setChannel(request.getHeader("X-Channel"));
            authContext.setDeviceId(request.getHeader("X-Device-ID"));

            // 4. Create Spring Security Authentication
            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(
                            authContext,
                            null,
                            authContext.getAuthorities()
                    );

            authentication.setDetails(
                    new WebAuthenticationDetailsSource().buildDetails(request)
            );

            // 5. Set authentication in SecurityContext
            SecurityContextHolder.getContext().setAuthentication(authentication);

            log.debug("Authentication successful: userId={}, sessionId={}",
                    claims.getUserId(), claims.getSessionId());

        } catch (TokenException e) {
            log.warn("Token validation failed: {}", e.getMessage());
            // Don't set authentication, let it proceed as unauthenticated
            // Security configuration will handle unauthorized access
        } catch (Exception e) {
            log.error("Error in JWT authentication filter", e);
        }

        // Continue filter chain
        filterChain.doFilter(request, response);
    }

    /**
     * Extract JWT token from Authorization header
     */
    private String extractToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(AppConstants.JWT_HEADER);

        if (bearerToken != null && bearerToken.startsWith(AppConstants.JWT_PREFIX)) {
            return bearerToken.substring(AppConstants.JWT_PREFIX.length());
        }

        return null;
    }

    /**
     * Get client IP address
     */
    private String getClientIp(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("X-Real-IP");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
        }
        // Handle multiple IPs (take first one)
        if (ip != null && ip.contains(",")) {
            ip = ip.split(",")[0].trim();
        }
        return ip;
    }

    /**
     * Skip filter for certain paths
     */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();

        // Skip authentication for public endpoints
        return path.startsWith("/api/v1/auth/login") ||
                path.startsWith("/api/v1/auth/refresh") ||
                path.startsWith("/api/v1/webhook") ||
                path.startsWith("/actuator") ||
                path.startsWith("/swagger-ui") ||
                path.startsWith("/v3/api-docs");
    }
}
