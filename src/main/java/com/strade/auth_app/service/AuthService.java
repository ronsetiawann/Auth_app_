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
 * Authentication service - COMPLETE VERSION
 *
 * ✅ All errors fixed
 * ✅ loginWithFirebase restored
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
            DeviceFingerprint deviceFingerprint = deviceFingerprintExtractor.extract(
                    httpRequest,
                    request.getChannel(),
                    request.getAppCode()
            );

            if (request.getDeviceId() != null) {
                deviceFingerprint.setDeviceId(request.getDeviceId());
            }

            String ipAddress = getClientIp(httpRequest);
            String userAgent = request.getUserAgent() != null ?
                    request.getUserAgent() : httpRequest.getHeader("User-Agent");

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
                    appProperties.getSecurity().getMfa().isEnforced(),
                    appProperties.getSecurity().getMinLoginHour() != null ?
                            appProperties.getSecurity().getMinLoginHour() : 1,
                    appProperties.getSecurity().getMinLoginMinute() != null ?
                            appProperties.getSecurity().getMinLoginMinute() : 0
            );

            if (!Boolean.TRUE.equals(result.getIsLoginSuccess())) {
                log.warn("Login failed for userId: {} - Code: {}, Message: {}",
                        request.getUserId(), result.getErrCode(), result.getLoginMessage());

                throw new AuthException(
                        ErrorCode.fromCode(result.getErrCode()),
                        result.getLoginMessage()
                );
            }

            if (Boolean.TRUE.equals(result.getMfaRequired())) {
                log.info("MFA required for userId: {}, sessionId: {}",
                        request.getUserId(), result.getSessionId());

                List<String> availableMethods = mfaService.getAvailableMfaMethods(
                        request.getUserId(),
                        deviceFingerprint.getDeviceId(),
                        request.getChannel()
                );

                eventLogService.logEvent(
                        request.getUserId(),
                        result.getSessionId(),
                        EventTypes.MFA_REQUIRED,
                        "MFA verification required - device not trusted"
                );

                return LoginResponse.mfaRequired(
                        result.getSessionId(),
                        availableMethods,
                        result.getLoginMessage()
                );
            }

            log.info("MFA not required for userId: {} - trusted device", request.getUserId());

            TokenResponse tokens = generateTokens(
                    request.getUserId(),
                    result.getSessionId(),
                    result.getKid()
            );

            authProcedureRepository.updateSessionJti(
                    result.getSessionId(),
                    result.getKid(),
                    extractJti(tokens.getAccessToken())
            );

            Session session = updateSessionToActive(result.getSessionId(), ipAddress, userAgent);

            if (session != null) {
                sessionCacheService.cacheSession(session);
            }

            eventLogService.logEvent(
                    request.getUserId(),
                    result.getSessionId(),
                    EventTypes.LOGIN_SUCCESS,
                    "Login successful without MFA (trusted device)"
            );

            log.info("Login successful for userId: {} (no MFA required)", request.getUserId());

            return LoginResponse.success(
                    tokens,
                    result.getSessionId(),
                    result.getLoginMessage()
            );

        } catch (AuthException e) {
            throw e;
        } catch (Exception e) {
            log.error("Login error for userId: {}", request.getUserId(), e);
            throw new AuthException(
                    ErrorCode.INTERNAL_SERVER_ERROR,
                    "Login failed due to system error"
            );
        }
    }

    /**
     * ✅ RESTORED: Firebase login (IDX Mobile)
     */
    @Transactional
    public LoginResponse loginWithFirebase(
            FirebaseLoginRequest request,
            HttpServletRequest httpRequest
    ) {
        log.info("Firebase login attempt: channel={}", request.getChannel());

        try {
            DeviceFingerprint deviceFingerprint = deviceFingerprintExtractor.extract(
                    httpRequest,
                    request.getChannel(),
                    null
            );

            String ipAddress = getClientIp(httpRequest);

            FirebaseLoginProcedureResult result = authProcedureRepository.loginIdxMobile(
                    request.getFirebaseToken(),
                    null,
                    request.getTerminal(),
                    request.getChannel(),
                    request.getVersion(),
                    deviceFingerprint.getDeviceId(),
                    request.getUserAgent(),
                    ipAddress,
                    appProperties.getSecurity().getMfa().isEnforced()
            );

            if (!Boolean.TRUE.equals(result.getIsLoginSuccess())) {
                log.warn("Firebase login failed: reason={}", result.getLoginMessage());
                throw new AuthException(
                        ErrorCode.fromCode(result.getErrCode()),
                        result.getLoginMessage()
                );
            }

            Session session = sessionRepository.findBySessionId(result.getSessionId())
                    .orElseThrow(() -> new AuthException(
                            ErrorCode.SESSION_NOT_FOUND,
                            "Session not found after Firebase login"
                    ));

            String userId = session.getUserId();

            if (Boolean.TRUE.equals(result.getMfaRequired())) {
                List<String> availableMethods = mfaService.getAvailableMfaMethods(
                        userId,
                        deviceFingerprint.getDeviceId(),
                        request.getChannel()
                );

                String loginMessage = loginValidationService.getLoginMessage(userId);

                return LoginResponse.mfaRequired(
                        result.getSessionId(),
                        availableMethods,
                        loginMessage
                );
            }

            TokenResponse tokens = generateTokens(
                    userId,
                    result.getSessionId(),
                    result.getKid()
            );

            authProcedureRepository.updateSessionJti(
                    result.getSessionId(),
                    result.getKid(),
                    extractJti(tokens.getAccessToken())
            );

            Session updatedSession = updateSessionToActive(result.getSessionId(), ipAddress, request.getUserAgent());

            if (updatedSession != null) {
                sessionCacheService.cacheSession(updatedSession);
            }

            log.info("Firebase login successful: userId={}, sessionId={}",
                    userId, result.getSessionId());

            String loginMessage = loginValidationService.getLoginMessage(userId);

            return LoginResponse.success(tokens, result.getSessionId(), loginMessage);

        } catch (AuthException e) {
            throw e;
        } catch (Exception e) {
            log.error("Firebase login error", e);
            throw new AuthException(ErrorCode.FIREBASE_AUTH_FAILED, "Firebase login failed", e);
        }
    }

    @Transactional
    public TokenResponse refreshToken(RefreshTokenRequest request) {
        log.debug("Token refresh attempt");

        try {
            byte[] tokenHash = HashUtil.sha256(request.getRefreshToken());

            var refreshToken = refreshTokenRepository.findByTokenHash(tokenHash)
                    .orElseThrow(() -> new AuthException(
                            ErrorCode.REFRESH_TOKEN_INVALID,
                            "Invalid refresh token"
                    ));

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

            String newAccessToken = jwtProvider.generateAccessToken(
                    session.getUserId(),
                    session.getSessionId(),
                    null
            );

            String newRefreshToken = jwtProvider.generateRefreshToken(session.getSessionId());
            byte[] newRefreshHash = jwtProvider.hashRefreshToken(newRefreshToken);
            LocalDateTime newRefreshExp = jwtProvider.getRefreshTokenExpiration();

            try {
                sessionProcedureRepository.rotateRefreshToken(
                        session.getSessionId(),
                        tokenHash,
                        newRefreshHash,
                        newRefreshExp
                );
            } catch (AuthException e) {
                if (e.getErrorCode() == ErrorCode.TOKEN_REUSE_DETECTED) {
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

    @Transactional
    public void logout(UUID sessionId, String reason) {
        log.info("Logout: sessionId={}", sessionId);

        try {
            Session session = sessionRepository.findBySessionId(sessionId)
                    .orElseThrow(() -> new AuthException(
                            ErrorCode.SESSION_NOT_FOUND,
                            "Session not found"
                    ));

            sessionProcedureRepository.revokeSession(
                    sessionId,
                    reason != null ? reason : "User logout"
            );

            sessionCacheService.invalidateSession(sessionId);

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

    @Transactional
    public void logoutAll(String userId, UUID exceptSessionId) {
        log.info("Logout all sessions: userId={}", userId);

        try {
            sessionProcedureRepository.revokeAllSessionsForUser(
                    userId,
                    exceptSessionId,
                    "User logout all sessions"
            );

            sessionCacheService.invalidateUserSessions(userId);

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

    // Helper methods
    private TokenResponse generateTokens(String userId, UUID sessionId, String kid) {
        String accessToken = jwtProvider.generateAccessToken(userId, sessionId, null);
        String refreshToken = jwtProvider.generateRefreshToken(sessionId);
        byte[] refreshHash = jwtProvider.hashRefreshToken(refreshToken);
        LocalDateTime refreshExp = jwtProvider.getRefreshTokenExpiration();

        sessionProcedureRepository.storeRefreshOnLogin(sessionId, refreshHash, refreshExp);

        return TokenResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .expiresIn(appProperties.getJwt().getAccessToken().getExpirationMinutes() * 60)
                .tokenType("Bearer")
                .build();
    }

    private Session updateSessionToActive(UUID sessionId, String ipAddress, String userAgent) {
        return sessionRepository.findBySessionId(sessionId)
                .map(session -> {
                    session.setStatus(AppConstants.SESSION_STATUS_ACTIVE);
                    session.setLastSeenAt(LocalDateTime.now());
                    session.setIpAddress(ipAddress);
                    session.setUserAgent(userAgent);
                    return sessionRepository.save(session);
                })
                .orElse(null);
    }

    private String extractJti(String token) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length >= 2) {
                String payload = new String(Base64.getUrlDecoder().decode(parts[1]));
                int jtiStart = payload.indexOf("\"jti\":\"") + 7;
                int jtiEnd = payload.indexOf("\"", jtiStart);
                return payload.substring(jtiStart, jtiEnd);
            }
        } catch (Exception e) {
            log.warn("Failed to extract JTI from token", e);
        }
        return null;
    }

    private String getClientIp(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("X-Real-IP");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
        }
        if (ip != null && ip.contains(",")) {
            ip = ip.split(",")[0].trim();
        }
        return ip;
    }
}