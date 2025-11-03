package com.strade.auth_app.service;

import com.strade.auth_app.config.properties.AppProperties;
import com.strade.auth_app.constant.AppConstants;
import com.strade.auth_app.constant.EventTypes;
import com.strade.auth_app.dto.request.FirebaseLoginRequest;
import com.strade.auth_app.dto.request.LoginRequest;
import com.strade.auth_app.dto.request.RefreshTokenRequest;
import com.strade.auth_app.dto.response.LoginResponse;
import com.strade.auth_app.dto.response.TokenResponse;
import com.strade.auth_app.entity.Session;
import com.strade.auth_app.exception.AuthException;
import com.strade.auth_app.exception.ErrorCode;
import com.strade.auth_app.repository.jpa.RefreshTokenRepository;
import com.strade.auth_app.repository.jpa.SessionRepository;
import com.strade.auth_app.repository.procedure.AuthProcedureRepository;
import com.strade.auth_app.repository.procedure.SessionProcedureRepository;
import com.strade.auth_app.repository.procedure.dto.FirebaseLoginProcedureResult;
import com.strade.auth_app.repository.procedure.dto.LoginProcedureResult;
import com.strade.auth_app.security.device.DeviceFingerprint;
import com.strade.auth_app.security.device.DeviceFingerprintExtractor;
import com.strade.auth_app.security.jwt.JwtProvider;
import com.strade.auth_app.service.cache.SessionCacheService;
import com.strade.auth_app.util.DateTimeUtil;
import com.strade.auth_app.util.HashUtil;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;

/**
 * Authentication service
 * Handles login, logout, token refresh
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class AuthService {

    private final AuthProcedureRepository authProcedureRepository;
    private final SessionProcedureRepository sessionProcedureRepository;
    private final SessionRepository sessionRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final SessionCacheService sessionCacheService;
    private final DeviceFingerprintExtractor deviceFingerprintExtractor;
    private final JwtProvider jwtProvider;
    private final MfaService mfaService;
    private final EventLogService eventLogService;
    private final LoginValidationService loginValidationService;
    private final AppProperties appProperties;

    /**
     * Standard login (RT/Web)
     */
    @Transactional
    public LoginResponse login(LoginRequest request, HttpServletRequest httpRequest) {
        log.info("Login attempt: userId={}, channel={}", request.getUserId(), request.getChannel());

        try {
            // ✅ 1. BUSINESS VALIDATION (from old SP logic)
            loginValidationService.validateLogin(
                    request.getUserId(),
                    request.getPassword(),
                    request.getTerminalId(),
                    request.getChannel()
            );

            // 2. Extract device fingerprint
            DeviceFingerprint deviceFingerprint = deviceFingerprintExtractor.extract(
                    httpRequest,
                    request.getChannel(),
                    request.getAppCode()
            );

            // Override with explicit deviceId if provided
            if (request.getDeviceId() != null) {
                deviceFingerprint.setDeviceId(request.getDeviceId());
            }

            String ipAddress = getClientIp(httpRequest);
            String userAgent = request.getUserAgent() != null ?
                    request.getUserAgent() : httpRequest.getHeader("User-Agent");

            // 3. Call stored procedure for login (simplified - no business validation in SP)
            LoginProcedureResult result = authProcedureRepository.selectUserLogon(
                    request.getUserId(),
                    request.getPassword(),
                    request.getChannel(),
                    request.getAppVersion(),
                    request.getServerNo(),
                    request.getTerminalId(),
                    request.getAppCode(),
                    deviceFingerprint.getDeviceId(),
                    userAgent,
                    appProperties.getSecurity().getMfa().isEnforced()
            );

            // 4. SP should always return success at this point (validation already done in step 1)
            if (!Boolean.TRUE.equals(result.getIsLoginSuccess())) {
                log.error("Unexpected: SP returned failure after passing validation. Message: {}",
                        result.getLoginMessage());

                throw new AuthException(
                        ErrorCode.AUTHENTICATION_FAILED,
                        result.getLoginMessage()
                );
            }

            // ✅ 5. Reset login retry counter on successful validation
            loginValidationService.resetLoginRetry(request.getUserId());

            // 6. Check if MFA required
            if (Boolean.TRUE.equals(result.getMfaRequired())) {
                log.info("MFA required for userId: {}", request.getUserId());

                // Get available MFA methods
                List<String> availableMethods = mfaService.getAvailableMfaMethods(
                        request.getUserId(),
                        deviceFingerprint.getDeviceId(),
                        request.getChannel()
                );

                // Log event
                eventLogService.logEvent(
                        request.getUserId(),
                        result.getSessionId(),
                        EventTypes.MFA_REQUIRED,
                        "MFA verification required"
                );

                // ✅ Get login message (last login info)
                String loginMessage = loginValidationService.getLoginMessage(request.getUserId());

                // ✅ FIXED: Added loginMessage parameter
                return LoginResponse.mfaRequired(
                        result.getSessionId(),
                        availableMethods,
                        loginMessage
                );
            }

            // 7. MFA not required - generate tokens
            TokenResponse tokens = generateTokens(
                    request.getUserId(),
                    result.getSessionId(),
                    result.getKid()
            );

            // 8. Update login success
            authProcedureRepository.updateUserLoginSuccess(
                    request.getUserId(),
                    DateTimeUtil.formatDisplay(LocalDateTime.now()),
                    request.getServerNo(),
                    request.getTerminalId(),
                    result.getSessionId(),
                    result.getKid(),
                    extractJti(tokens.getAccessToken()),
                    ipAddress,
                    userAgent
            );

            // 9. Update session status to ACTIVE
            updateSessionToActive(result.getSessionId(), ipAddress, userAgent);

            // 10. Log event
            eventLogService.logEvent(
                    request.getUserId(),
                    result.getSessionId(),
                    EventTypes.LOGIN_SUCCESS,
                    "Login successful without MFA"
            );

            log.info("Login successful: userId={}, sessionId={}",
                    request.getUserId(), result.getSessionId());

            // ✅ Get login message (last login info)
            String loginMessage = loginValidationService.getLoginMessage(request.getUserId());

            // ✅ FIXED: Added loginMessage parameter
            return LoginResponse.success(tokens, result.getSessionId(), loginMessage);

        } catch (AuthException e) {
            // ✅ Log failure event
            eventLogService.logEvent(
                    request.getUserId(),
                    null,
                    EventTypes.LOGIN_FAILED,
                    e.getMessage()
            );
            throw e; // Re-throw to GlobalExceptionHandler
        } catch (Exception e) {
            log.error("Login error: userId={}", request.getUserId(), e);

            // Log failure event
            eventLogService.logEvent(
                    request.getUserId(),
                    null,
                    EventTypes.LOGIN_FAILED,
                    "Unexpected error: " + e.getMessage()
            );

            throw new AuthException(ErrorCode.AUTHENTICATION_FAILED, "Login failed", e);
        }
    }

    /**
     * Firebase login (IDX Mobile)
     */
    @Transactional
    public LoginResponse loginWithFirebase(
            FirebaseLoginRequest request,
            HttpServletRequest httpRequest
    ) {
        log.info("Firebase login attempt: channel={}", request.getChannel());

        try {
            // 1. Extract device fingerprint
            DeviceFingerprint deviceFingerprint = deviceFingerprintExtractor.extract(
                    httpRequest,
                    request.getChannel(),
                    null
            );

            String ipAddress = getClientIp(httpRequest);

            // 2. Call stored procedure for Firebase login
            FirebaseLoginProcedureResult result = authProcedureRepository.loginIdxMobile(
                    request.getFirebaseToken(),
                    null, // UserId determined by Firebase
                    request.getTerminal(),
                    request.getChannel(),
                    request.getVersion(),
                    deviceFingerprint.getDeviceId(),
                    request.getUserAgent(),
                    ipAddress,
                    appProperties.getSecurity().getMfa().isEnforced()
            );

            // 3. Check result
            if (!Boolean.TRUE.equals(result.getIsLoginSuccess())) {
                log.warn("Firebase login failed: reason={}", result.getLoginMessage());
                throw new AuthException(
                        ErrorCode.FIREBASE_AUTH_FAILED,
                        result.getLoginMessage()
                );
            }

            // 4. Get session to retrieve userId
            Session session = sessionRepository.findBySessionId(result.getSessionId())
                    .orElseThrow(() -> new AuthException(
                            ErrorCode.SESSION_NOT_FOUND,
                            "Session not found after Firebase login"
                    ));

            String userId = session.getUserId();

            // 5. Check if MFA required
            if (Boolean.TRUE.equals(result.getMfaRequired())) {
                List<String> availableMethods = mfaService.getAvailableMfaMethods(
                        userId,
                        deviceFingerprint.getDeviceId(),
                        request.getChannel()
                );

                // ✅ Get login message
                String loginMessage = loginValidationService.getLoginMessage(userId);

                // ✅ FIXED: Added loginMessage parameter
                return LoginResponse.mfaRequired(
                        result.getSessionId(),
                        availableMethods,
                        loginMessage
                );
            }

            // 6. Generate tokens
            TokenResponse tokens = generateTokens(
                    userId,
                    result.getSessionId(),
                    result.getKid()
            );

            // 7. Update session to active
            updateSessionToActive(result.getSessionId(), ipAddress, request.getUserAgent());

            log.info("Firebase login successful: userId={}, sessionId={}",
                    userId, result.getSessionId());

            // ✅ Get login message
            String loginMessage = loginValidationService.getLoginMessage(userId);

            // ✅ FIXED: Added loginMessage parameter
            return LoginResponse.success(tokens, result.getSessionId(), loginMessage);

        } catch (AuthException e) {
            throw e;
        } catch (Exception e) {
            log.error("Firebase login error", e);
            throw new AuthException(ErrorCode.FIREBASE_AUTH_FAILED, "Firebase login failed", e);
        }
    }

    /**
     * Refresh access token
     */
    @Transactional
    public TokenResponse refreshToken(RefreshTokenRequest request) {
        log.debug("Token refresh attempt");

        try {
            // 1. Hash refresh token
            byte[] tokenHash = HashUtil.sha256(request.getRefreshToken());

            // 2. Find refresh token in database
            var refreshToken = refreshTokenRepository.findByTokenHash(tokenHash)
                    .orElseThrow(() -> new AuthException(
                            ErrorCode.REFRESH_TOKEN_INVALID,
                            "Invalid refresh token"
                    ));

            // 3. Validate refresh token
            if (refreshToken.getRevokedAt() != null) {
                log.warn("Revoked refresh token used: {}", refreshToken.getRefreshId());
                throw new AuthException(
                        ErrorCode.REFRESH_TOKEN_REVOKED,
                        "Refresh token has been revoked"
                );
            }

            if (DateTimeUtil.isPast(refreshToken.getExpiresAt())) {
                log.warn("Expired refresh token used: {}", refreshToken.getRefreshId());
                throw new AuthException(
                        ErrorCode.REFRESH_TOKEN_EXPIRED,
                        "Refresh token has expired"
                );
            }

            // 4. Get session
            Session session = sessionRepository.findBySessionId(refreshToken.getSessionId())
                    .orElseThrow(() -> new AuthException(
                            ErrorCode.SESSION_NOT_FOUND,
                            "Session not found"
                    ));

            if (session.getStatus() != AppConstants.SESSION_STATUS_ACTIVE) {
                throw new AuthException(
                        ErrorCode.SESSION_INACTIVE,
                        "Session is not active"
                );
            }

            // 5. Generate new tokens
            String newAccessToken = jwtProvider.generateAccessToken(
                    session.getUserId(),
                    session.getSessionId(),
                    null
            );

            String newRefreshToken = jwtProvider.generateRefreshToken(session.getSessionId());
            byte[] newRefreshHash = jwtProvider.hashRefreshToken(newRefreshToken);
            LocalDateTime newRefreshExp = jwtProvider.getRefreshTokenExpiration();

            // 6. Rotate refresh token (with reuse detection)
            try {
                sessionProcedureRepository.rotateRefreshToken(
                        session.getSessionId(),
                        tokenHash,
                        newRefreshHash,
                        newRefreshExp
                );
            } catch (AuthException e) {
                if (e.getErrorCode() == ErrorCode.TOKEN_REUSE_DETECTED) {
                    // Revoke all sessions for this user
                    sessionProcedureRepository.revokeAllSessionsForUser(
                            session.getUserId(),
                            null,
                            "Refresh token reuse detected"
                    );

                    eventLogService.logEvent(
                            session.getUserId(),
                            session.getSessionId(),
                            EventTypes.REFRESH_REUSE_DETECTED,
                            "Refresh token reuse - all sessions revoked"
                    );
                }
                throw e;
            }

            // 7. Update session last seen
            session.setLastSeenAt(LocalDateTime.now());
            sessionRepository.save(session);
            sessionCacheService.cacheSession(session);

            log.info("Token refreshed: userId={}, sessionId={}",
                    session.getUserId(), session.getSessionId());

            return TokenResponse.builder()
                    .accessToken(newAccessToken)
                    .refreshToken(newRefreshToken)
                    .expiresIn(appProperties.getJwt().getAccessToken().getExpirationMinutes() * 60)
                    .tokenType("Bearer")
                    .build();

        } catch (AuthException e) {
            throw e;
        } catch (Exception e) {
            log.error("Token refresh error", e);
            throw new AuthException(ErrorCode.REFRESH_TOKEN_INVALID, "Token refresh failed", e);
        }
    }

    /**
     * Logout - revoke current session
     */
    @Transactional
    public void logout(UUID sessionId, String reason) {
        log.info("Logout: sessionId={}", sessionId);

        try {
            // Get session for userId
            Session session = sessionRepository.findBySessionId(sessionId)
                    .orElseThrow(() -> new AuthException(
                            ErrorCode.SESSION_NOT_FOUND,
                            "Session not found"
                    ));

            // Revoke session
            sessionProcedureRepository.revokeSession(
                    sessionId,
                    reason != null ? reason : "User logout"
            );

            // Invalidate cache
            sessionCacheService.invalidateSession(sessionId);

            // Log event
            eventLogService.logEvent(
                    session.getUserId(),
                    sessionId,
                    EventTypes.LOGOUT,
                    "User logged out"
            );

            log.info("Logout successful: sessionId={}", sessionId);

        } catch (AuthException e) {
            throw e;
        } catch (Exception e) {
            log.error("Logout error: sessionId={}", sessionId, e);
            throw new AuthException(ErrorCode.INTERNAL_SERVER_ERROR, "Logout failed", e);
        }
    }

    /**
     * Logout all sessions for user
     */
    @Transactional
    public void logoutAll(String userId, UUID exceptSessionId) {
        log.info("Logout all sessions: userId={}", userId);

        try {
            sessionProcedureRepository.revokeAllSessionsForUser(
                    userId,
                    exceptSessionId,
                    "User logout all sessions"
            );

            // Invalidate cache
            sessionCacheService.invalidateUserSessions(userId);

            // Log event
            eventLogService.logEvent(
                    userId,
                    exceptSessionId,
                    EventTypes.LOGOUT_ALL,
                    "All sessions logged out"
            );

            log.info("Logout all successful: userId={}", userId);

        } catch (Exception e) {
            log.error("Logout all error: userId={}", userId, e);
            throw new AuthException(ErrorCode.INTERNAL_SERVER_ERROR, "Logout all failed", e);
        }
    }

    // ========================================
    // Private Helper Methods
    // ========================================

    /**
     * Generate access and refresh tokens
     */
    private TokenResponse generateTokens(String userId, UUID sessionId, String kid) {
        // Generate access token
        String accessToken = jwtProvider.generateAccessToken(userId, sessionId, null);

        // Generate refresh token
        String refreshToken = jwtProvider.generateRefreshToken(sessionId);
        byte[] refreshHash = jwtProvider.hashRefreshToken(refreshToken);
        LocalDateTime refreshExp = jwtProvider.getRefreshTokenExpiration();

        // Store refresh token in database
        sessionProcedureRepository.storeRefreshOnLogin(sessionId, refreshHash, refreshExp);

        return TokenResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .expiresIn(appProperties.getJwt().getAccessToken().getExpirationMinutes() * 60)
                .tokenType("Bearer")
                .build();
    }

    /**
     * Update session status to ACTIVE
     */
    private void updateSessionToActive(UUID sessionId, String ipAddress, String userAgent) {
        sessionRepository.findBySessionId(sessionId).ifPresent(session -> {
            session.setStatus(AppConstants.SESSION_STATUS_ACTIVE);
            session.setLastSeenAt(LocalDateTime.now());
            session.setIpAddress(ipAddress);
            session.setUserAgent(userAgent);
            sessionRepository.save(session);
            sessionCacheService.cacheSession(session);
        });
    }

    /**
     * Extract JTI from JWT token
     */
    private String extractJti(String token) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length >= 2) {
                String payload = new String(Base64.getUrlDecoder().decode(parts[1]));
                // Simple extraction (in production, use proper JSON parsing)
                int jtiStart = payload.indexOf("\"jti\":\"") + 7;
                int jtiEnd = payload.indexOf("\"", jtiStart);
                return payload.substring(jtiStart, jtiEnd);
            }
        } catch (Exception e) {
            log.warn("Failed to extract JTI from token", e);
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
}