package com.strade.auth_app.service;

import com.strade.auth_app.config.properties.AppProperties;
import com.strade.auth_app.config.properties.SecurityProperties;
import com.strade.auth_app.constant.AppConstants;
import com.strade.auth_app.constant.EventTypes;
import com.strade.auth_app.dto.request.OtpVerifyRequest;
import com.strade.auth_app.dto.request.TotpActivateRequest;
import com.strade.auth_app.dto.request.TotpVerifyRequest;
import com.strade.auth_app.dto.response.MfaStatusResponse;
import com.strade.auth_app.dto.response.MfaVerifyResponse;
import com.strade.auth_app.dto.response.TotpSetupResponse;
import com.strade.auth_app.entity.Session;
import com.strade.auth_app.entity.UserMfa;
import com.strade.auth_app.entity.UserMfaBackupCode;
import com.strade.auth_app.exception.AuthException;
import com.strade.auth_app.exception.ErrorCode;
import com.strade.auth_app.exception.MfaException;
import com.strade.auth_app.repository.jpa.SessionRepository;
import com.strade.auth_app.repository.jpa.UserMfaBackupCodeRepository;
import com.strade.auth_app.repository.jpa.UserMfaRepository;
import com.strade.auth_app.repository.procedure.AuthProcedureRepository;
import com.strade.auth_app.repository.procedure.MfaProcedureRepository;
import com.strade.auth_app.repository.procedure.SessionProcedureRepository;
import com.strade.auth_app.security.jwt.JwtProvider;
import com.strade.auth_app.security.totp.TotpValidator;
import com.strade.auth_app.service.cache.RateLimitCacheService;
import com.strade.auth_app.service.cache.SessionCacheService;
import com.strade.auth_app.service.cache.TrustedDeviceCacheService;
import com.strade.auth_app.util.DateTimeUtil;
import com.strade.auth_app.util.EncryptionUtil;
import com.strade.auth_app.util.HashUtil;
import com.strade.auth_app.util.RandomUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;

/**
 * Multi-Factor Authentication service
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class MfaService {

    private final UserMfaRepository userMfaRepository;
    private final UserMfaBackupCodeRepository backupCodeRepository;
    private final SessionRepository sessionRepository;
    private final MfaProcedureRepository mfaProcedureRepository;
    private final SessionProcedureRepository sessionProcedureRepository;
    private final AuthProcedureRepository authProcedureRepository;
    private final TotpValidator totpValidator;
    private final SessionCacheService sessionCacheService;
    private final TrustedDeviceCacheService trustedDeviceCacheService;
    private final RateLimitCacheService rateLimitCacheService;
    private final EventLogService eventLogService;
    private final DeviceService deviceService;
    private final AppProperties appProperties;
    private final JwtProvider jwtProvider;
    private final SecurityProperties securityProperties;

    /**
     * Get available MFA methods for user
     */
    public List<String> getAvailableMfaMethods(String userId, String deviceId, String channel) {
        List<String> methods = new ArrayList<>();

        // Check if device is trusted
        Boolean isTrusted = trustedDeviceCacheService.getCachedTrustedDevice(userId, deviceId, channel);
        if (isTrusted == null) {
            isTrusted = deviceService.isTrustedDevice(userId, deviceId, channel);
        }

        if (Boolean.TRUE.equals(isTrusted)) {
            log.debug("Device is trusted, MFA not required: userId={}, deviceId={}", userId, deviceId);
            return methods;
        }

        // Get configured MFA methods
        Set<String> configuredMethods = securityProperties.getMfa().getNormalizedAvailableMethods();

        // Check TOTP (only if configured)
        if (configuredMethods.contains("totp")) {
            Optional<UserMfa> userMfaOpt = userMfaRepository.findByUserId(userId);

            if (userMfaOpt.isPresent() && userMfaOpt.get().isTotpActive()) {
                // TOTP is activated
                methods.add("totp");
            } else if (!securityProperties.getMfa().isTotpSetupRequiresAuth()) {
                // TOTP not activated but can setup during MFA flow
                methods.add("totp");
            }
        }

        // Add configured OTP methods
        if (configuredMethods.contains("otp_sms")) {
            methods.add("otp_sms");
        }
        if (configuredMethods.contains("otp_email")) {
            methods.add("otp_email");
        }
        if (configuredMethods.contains("otp_whatsapp")) {
            methods.add("otp_whatsapp");
        }

        return methods;
    }

    /**
     * Get MFA status for user
     */
    public MfaStatusResponse getMfaStatus(String userId) {
        UserMfa userMfa = userMfaRepository.findByUserId(userId)
                .orElse(null);

        if (userMfa == null) {
            return MfaStatusResponse.builder()
                    .totpEnabled(false)
                    .totpStatus((byte) 0)
                    .enforced(appProperties.getSecurity().getMfa().isEnforced())
                    .backupCodesRemaining(0)
                    .backupCodesTotal(0)
                    .build();
        }

        long backupCodesRemaining = backupCodeRepository.countAvailableCodesByUserId(userId);

        return MfaStatusResponse.builder()
                .totpEnabled(userMfa.getTotpEnabled())
                .totpStatus(userMfa.getTotpStatus())
                .enforced(userMfa.getEnforced())
                .backupCodesRemaining((int) backupCodesRemaining)
                .backupCodesTotal(appProperties.getSecurity().getMfa().getBackupCodes().getCount())
                .build();
    }

    /**
     * Setup TOTP for user
     */
    @Transactional
    public TotpSetupResponse setupTotp(String userId) {
        log.info("Setting up TOTP for user: {}", userId);
        try {
            // Check if already enabled
            userMfaRepository.findByUserId(userId).ifPresent(existing -> {
                if (existing.isTotpActive()) {
                    throw new MfaException(
                            ErrorCode.MFA_ALREADY_ENABLED,
                            "TOTP is already enabled"
                    );
                }
            });

            // Generate TOTP secret
            String secret = totpValidator.generateSecret();

            // Encrypt secret
            String encryptionKey = appProperties.getSecurity().getEncryptionKey();
            byte[] encryptedSecret = EncryptionUtil.encrypt(secret, encryptionKey);

            // Generate backup codes
            List<String> backupCodes = RandomUtil.generateBackupCodes(
                    appProperties.getSecurity().getMfa().getBackupCodes().getCount()
            );

            // Save UserMfa (INACTIVE until verified)
            UserMfa userMfa = userMfaRepository.findByUserId(userId)
                    .orElse(UserMfa.builder()
                            .userId(userId)
                            .build());

            userMfa.setTotpSecretEnc(encryptedSecret);
            userMfa.setTotpEnabled(false);
            userMfa.setEnforced(false);
            userMfa.setTotpStatus((byte) 0); // INACTIVE
            userMfa.setTotpDigits(appProperties.getSecurity().getMfa().getTotp().getDigits().byteValue());
            userMfa.setTotpPeriodSeconds(appProperties.getSecurity().getMfa().getTotp().getPeriodSeconds().shortValue());
            userMfa.setTotpAlgorithm(appProperties.getSecurity().getMfa().getTotp().getAlgorithm());
            userMfa.setCreatedAt(LocalDateTime.now());

            userMfaRepository.save(userMfa);

            // Save backup codes (hashed)
            saveBackupCodes(userId, backupCodes);

            // Generate QR code URI
            String qrCodeUri = totpValidator.generateQrCodeUri(secret, userId);

            log.info("TOTP setup initiated for user: {}", userId);

            return TotpSetupResponse.builder()
                    .secret(secret)
                    .qrCodeUri(qrCodeUri)
                    .backupCodes(backupCodes)
                    .issuer(appProperties.getSecurity().getMfa().getTotp().getIssuer())
                    .digits(appProperties.getSecurity().getMfa().getTotp().getDigits())
                    .period(appProperties.getSecurity().getMfa().getTotp().getPeriodSeconds())
                    .algorithm(appProperties.getSecurity().getMfa().getTotp().getAlgorithm())
                    .build();
        } catch (Exception e) {
            log.error("Error during TOTP setup for user: {}", userId, e);
            throw new MfaException(
                    ErrorCode.INTERNAL_SERVER_ERROR,
                    "Failed to set up TOTP: " + e.getMessage(),
                    e
            );
        }
    }

    /**
     * Activate TOTP (verify first code)
     */
    @Transactional
    public void activateTotp(String userId, TotpActivateRequest request) {
        log.info("Activating TOTP for user: {}", userId);

        // Get user MFA config
        UserMfa userMfa = userMfaRepository.findByUserId(userId)
                .orElseThrow(() -> new MfaException(
                        ErrorCode.TOTP_NOT_SETUP,
                        "TOTP is not set up"
                ));

        if (userMfa.isTotpActive()) {
            throw new MfaException(
                    ErrorCode.MFA_ALREADY_ENABLED,
                    "TOTP is already activated"
            );
        }

        // Decrypt secret
        String encryptionKey = appProperties.getSecurity().getEncryptionKey();
        String secret = EncryptionUtil.decrypt(userMfa.getTotpSecretEnc(), encryptionKey);

        // Verify TOTP code
        try {
            totpValidator.validateCode(secret, request.getCode(), null);
        } catch (MfaException e) {
            throw new MfaException(
                    ErrorCode.TOTP_INVALID,
                    "Invalid verification code"
            );
        }

        // Activate TOTP
        userMfa.setTotpEnabled(true);
        userMfa.setTotpStatus((byte) 1); // ACTIVE
        userMfa.setActivatedAt(LocalDateTime.now());
        userMfa.setActivationChannel("web");
        userMfa.setActivationMethod("manual");

        userMfaRepository.save(userMfa);

        // Log event
        eventLogService.logEvent(userId, null, EventTypes.TOTP_ENABLED, "TOTP activated");

        log.info("TOTP activated successfully for user: {}", userId);
    }

    /**
     * Verify TOTP for login
     */
    @Transactional
    public void verifyTotpForLogin(TotpVerifyRequest request) {
        log.info("Verifying TOTP for sessionId: {}", request.getSessionId());

        // Rate limit check
        rateLimitCacheService.checkAndIncrement(
                "totp_verify",
                request.getSessionId().toString(),
                5,
                300 // 5 attempts per 5 minutes
        );

        // Get session
        Session session = sessionRepository.findBySessionId(request.getSessionId())
                .orElseThrow(() -> new AuthException(
                        ErrorCode.SESSION_NOT_FOUND,
                        "Session not found"
                ));

        if (session.getStatus() != AppConstants.SESSION_STATUS_PENDING) {
            throw new AuthException(
                    ErrorCode.SESSION_INACTIVE,
                    "Session is not pending MFA"
            );
        }

        String userId = session.getUserId();

        // Get user MFA config
        UserMfa userMfa = userMfaRepository.findByUserId(userId)
                .orElseThrow(() -> new MfaException(
                        ErrorCode.TOTP_NOT_SETUP,
                        "TOTP is not set up"
                ));

        if (!userMfa.isTotpActive()) {
            throw new MfaException(
                    ErrorCode.TOTP_NOT_SETUP,
                    "TOTP is not active"
            );
        }

        // Decrypt secret
        String encryptionKey = appProperties.getSecurity().getEncryptionKey();
        String secret = EncryptionUtil.decrypt(userMfa.getTotpSecretEnc(), encryptionKey);

        // Verify TOTP code
        long currentTimeStep;
        try {
            currentTimeStep = totpValidator.validateCode(
                    secret,
                    request.getCode(),
                    userMfa.getLastUsedTimeStep()
            );
        } catch (MfaException e) {
            log.warn("TOTP verification failed for user: {}", userId);
            throw e;
        }

        // Update last used time step
        userMfa.setLastUsedTimeStep(currentTimeStep);
        userMfaRepository.save(userMfa);

        // Call stored procedure to complete MFA
        mfaProcedureRepository.verifyTotpForLogin(
                userId,
                request.getSessionId(),
                true, // TOTP verified
                request.getTrustThisDevice(),
                appProperties.getSecurity().getMfa().getTrustedDevice().getTtlDays(),
                request.getDeviceType(),
                request.getDeviceName(),
                appProperties.getSecurity().getMfa().getTrustedDevice().getMaxDevices(),
                appProperties.getSecurity().getMfa().getTrustedDevice().isSendEmailNotification()
        );

        // Update session to ACTIVE
        session.setStatus(AppConstants.SESSION_STATUS_ACTIVE);
        //session.setMfaCompletedAt(LocalDateTime.now());
        session.setMfaMethod("totp");
        sessionRepository.save(session);
        sessionCacheService.cacheSession(session);

        // Reset rate limit
        rateLimitCacheService.reset("totp_verify", request.getSessionId().toString());

        // Log event
        eventLogService.logEvent(
                userId,
                request.getSessionId(),
                EventTypes.TOTP_VERIFIED,
                "TOTP verified successfully"
        );

        log.info("TOTP verification successful for user: {}", userId);
    }

    /**
     * Verify OTP for login
     */
    @Transactional
    public MfaVerifyResponse verifyOtpForLogin(OtpVerifyRequest request) {
        log.info("Verifying OTP for sessionId: {}, challengeId: {}",
                request.getSessionId(), request.getChallengeId());

        // Rate limit check
        rateLimitCacheService.checkAndIncrement(
                "otp_verify",
                request.getChallengeId().toString(),
                appProperties.getSecurity().getMfa().getOtp().getMaxAttempts(),
                appProperties.getSecurity().getMfa().getOtp().getTtlSeconds()
        );

        // Get session
        Session session = sessionRepository.findBySessionId(request.getSessionId())
                .orElseThrow(() -> new AuthException(
                        ErrorCode.SESSION_NOT_FOUND,
                        "Session not found"
                ));

        if (session.getStatus() != AppConstants.SESSION_STATUS_PENDING) {
            throw new AuthException(
                    ErrorCode.SESSION_INACTIVE,
                    "Session is not pending MFA"
            );
        }

        String userId = session.getUserId();

        // Hash OTP code
        byte[] codeHash = HashUtil.sha256WithSalt(request.getCode());

        // Call stored procedure to verify OTP
        try {
            mfaProcedureRepository.verifyOtpForLogin(
                    userId,
                    request.getSessionId(),
                    request.getChallengeId(),
                    codeHash,
                    request.getTrustThisDevice(),
                    appProperties.getSecurity().getMfa().getTrustedDevice().getTtlDays(),
                    request.getDeviceType(),
                    request.getDeviceName(),
                    appProperties.getSecurity().getMfa().getTrustedDevice().getMaxDevices(),
                    appProperties.getSecurity().getMfa().getTrustedDevice().isSendEmailNotification()
            );
        } catch (AuthException e) {
            log.warn("OTP verification failed for user: {}", userId);
            throw e;
        }

        // Reset rate limit
        rateLimitCacheService.reset("otp_verify", request.getChallengeId().toString());

        // Log event
        eventLogService.logEvent(
                userId,
                request.getSessionId(),
                EventTypes.OTP_VERIFIED,
                "OTP verified successfully"
        );

        log.info("OTP verification successful for user: {}", userId);

        // ✅ Complete login and generate tokens (same as AuthService)
        return completeLoginAfterMfa(session);
    }
    /**
     * Generate tokens and complete login via stored procedure
     */
    /**
     * Complete login after MFA verification and generate tokens
     */
    private MfaVerifyResponse completeLoginAfterMfa(Session session) {
        String userId = session.getUserId();
        UUID sessionId = session.getSessionId();
        String kid = session.getJwtKid();

        try {
            // 1. Generate tokens
            log.debug("Generating tokens for userId: {}", userId);
            String accessToken = jwtProvider.generateAccessToken(userId, sessionId, null);
            String refreshToken = jwtProvider.generateRefreshToken(sessionId);
            byte[] refreshHash = jwtProvider.hashRefreshToken(refreshToken);
            LocalDateTime refreshExp = jwtProvider.getRefreshTokenExpiration();

            // 2. Store refresh token via SP
            log.debug("Storing refresh token for sessionId: {}", sessionId);
            sessionProcedureRepository.storeRefreshOnLogin(sessionId, refreshHash, refreshExp);

            // 3. Update login success via SP
            log.debug("Updating login success for userId: {}", userId);
            authProcedureRepository.updateUserLoginSuccess(
                    userId,
                    DateTimeUtil.formatDisplay(LocalDateTime.now()),
                    session.getServerNo(),
                    session.getTerminalId(),
                    sessionId,
                    kid,
                    extractJti(accessToken),
                    session.getIpAddress(),
                    session.getUserAgent()
            );

            // 4. Update session to ACTIVE
            log.debug("Updating session to ACTIVE for sessionId: {}", sessionId);
            session.setStatus(AppConstants.SESSION_STATUS_ACTIVE);
            session.setLastSeenAt(LocalDateTime.now());
            sessionRepository.save(session);
            sessionCacheService.cacheSession(session);

            // 5. Log event
            eventLogService.logEvent(
                    userId,
                    sessionId,
                    EventTypes.MFA_COMPLETED,
                    "MFA completed, tokens issued"
            );

            log.info("MFA login completed successfully: userId={}, sessionId={}", userId, sessionId);

            // 6. Return response
            long expiresIn = appProperties.getJwt().getAccessToken().getExpirationMinutes() * 60;

            return MfaVerifyResponse.builder()
                    .accessToken(accessToken)
                    .refreshToken(refreshToken)
                    .tokenType("Bearer")
                    .expiresIn(expiresIn)
                    .sessionId(sessionId.toString())
                    .build();

        } catch (Exception e) {
            log.error("Error completing MFA login for userId: {}, sessionId: {}",
                    userId, sessionId, e);
            throw new AuthException(
                    ErrorCode.INTERNAL_SERVER_ERROR,
                    "Failed to complete MFA login: " + e.getMessage(),
                    e
            );
        }
    }

    /**
     * Extract JTI from JWT token (copy from AuthService)
     */
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

    /**
     * Disable TOTP
     */
    @Transactional
    public void disableTotp(String userId) {
        log.info("Disabling TOTP for user: {}", userId);

        UserMfa userMfa = userMfaRepository.findByUserId(userId)
                .orElseThrow(() -> new MfaException(
                        ErrorCode.TOTP_NOT_SETUP,
                        "TOTP is not set up"
                ));

        userMfa.setTotpEnabled(false);
        userMfa.setTotpStatus((byte) 0); // INACTIVE
        userMfa.setDeactivatedAt(LocalDateTime.now());

        userMfaRepository.save(userMfa);

        // Delete backup codes
        backupCodeRepository.deleteByUserId(userId);

        // Log event
        eventLogService.logEvent(userId, null, EventTypes.TOTP_DISABLED, "TOTP disabled");

        log.info("TOTP disabled for user: {}", userId);
    }

    /**
     * Regenerate backup codes
     */
    @Transactional
    public List<String> regenerateBackupCodes(String userId) {
        log.info("Regenerating backup codes for user: {}", userId);

        // Check if TOTP is enabled
        userMfaRepository.findByUserId(userId)
                .filter(UserMfa::isTotpActive)
                .orElseThrow(() -> new MfaException(
                        ErrorCode.TOTP_NOT_SETUP,
                        "TOTP must be enabled to generate backup codes"
                ));

        // Delete old backup codes
        backupCodeRepository.deleteByUserId(userId);

        // Generate new codes
        List<String> backupCodes = RandomUtil.generateBackupCodes(
                appProperties.getSecurity().getMfa().getBackupCodes().getCount()
        );

        // Save new codes
        saveBackupCodes(userId, backupCodes);

        log.info("Backup codes regenerated for user: {}", userId);

        return backupCodes;
    }

    // ========================================
    // Private Helper Methods
    // ========================================

    /**
     * Save backup codes (hashed)
     */
    private void saveBackupCodes(String userId, List<String> codes) {
        for (String code : codes) {
            // Remove hyphens and hash
            String cleanCode = code.replace("-", "");
            byte[] codeHash = HashUtil.sha256WithSalt(cleanCode);

            UserMfaBackupCode backupCode = UserMfaBackupCode.builder()
                    .userId(userId)
                    .codeHash(codeHash)
                    .createdAt(LocalDateTime.now())
                    .build();

            backupCodeRepository.save(backupCode);
        }
    }
}
