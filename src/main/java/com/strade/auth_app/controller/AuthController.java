package com.strade.auth_app.controller;

import com.strade.auth_app.dto.request.FirebaseLoginRequest;
import com.strade.auth_app.dto.request.LoginRequest;
import com.strade.auth_app.dto.request.RefreshTokenRequest;
import com.strade.auth_app.dto.response.ApiResponse;
import com.strade.auth_app.dto.response.LoginResponse;
import com.strade.auth_app.dto.response.TokenResponse;
import com.strade.auth_app.security.SecurityContextUtil;
import com.strade.auth_app.service.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

/**
 * Authentication REST API Controller
 */
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Authentication", description = "Authentication APIs")
public class AuthController {

    private final AuthService authService;

    /**
     * Standard login (RT/Web)
     * POST /api/v1/auth/login
     */
    @PostMapping("/login")
    @Operation(summary = "User login", description = "Authenticate user with username and password")
    public ResponseEntity<ApiResponse<LoginResponse>> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest
    ) {
        log.info("Login request: userId={}, channel={}", request.getUserId(), request.getChannel());

        LoginResponse response = authService.login(request, httpRequest);

        return ResponseEntity.ok(ApiResponse.success(response));
    }

    /**
     * Firebase login (IDX Mobile)
     * POST /api/v1/auth/login/firebase
     */
    @PostMapping("/login/firebase")
    @Operation(summary = "Firebase login", description = "Authenticate user with Firebase token")
    public ResponseEntity<ApiResponse<LoginResponse>> loginWithFirebase(
            @Valid @RequestBody FirebaseLoginRequest request,
            HttpServletRequest httpRequest
    ) {
        log.info("Firebase login request: channel={}", request.getChannel());

        LoginResponse response = authService.loginWithFirebase(request, httpRequest);

        return ResponseEntity.ok(ApiResponse.success(response));
    }

    /**
     * Refresh access token
     * POST /api/v1/auth/refresh
     */
    @PostMapping("/refresh")
    @Operation(summary = "Refresh token", description = "Get new access token using refresh token")
    public ResponseEntity<ApiResponse<TokenResponse>> refresh(
            @Valid @RequestBody RefreshTokenRequest request
    ) {
        log.debug("Token refresh request");

        TokenResponse response = authService.refreshToken(request);

        return ResponseEntity.ok(ApiResponse.success(response));
    }

    /**
     * Logout current session
     * POST /api/v1/auth/logout
     */
    @PostMapping("/logout")
    @Operation(summary = "Logout", description = "Logout current session")
    public ResponseEntity<ApiResponse<Void>> logout() {
        UUID sessionId = SecurityContextUtil.getCurrentSessionId()
                .orElseThrow(() -> new IllegalStateException("No active session"));

        log.info("Logout request: sessionId={}", sessionId);

        authService.logout(sessionId, "User logout");

        return ResponseEntity.ok(ApiResponse.success(null));
    }

    /**
     * Logout all sessions
     * POST /api/v1/auth/logout/all
     */
    @PostMapping("/logout/all")
    @Operation(summary = "Logout all sessions", description = "Logout all sessions except current")
    public ResponseEntity<ApiResponse<Void>> logoutAll(
            @RequestParam(required = false, defaultValue = "false") Boolean includeCurrent
    ) {
        String userId = SecurityContextUtil.getCurrentUserId()
                .orElseThrow(() -> new IllegalStateException("Not authenticated"));

        UUID currentSessionId = SecurityContextUtil.getCurrentSessionId().orElse(null);
        UUID exceptSessionId = Boolean.TRUE.equals(includeCurrent) ? null : currentSessionId;

        log.info("Logout all sessions: userId={}, includeCurrent={}", userId, includeCurrent);

        authService.logoutAll(userId, exceptSessionId);

        return ResponseEntity.ok(ApiResponse.success(null));
    }
}
