package com.strade.auth_app.repository.procedure;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Repository for MFA-related stored procedures
 */
public interface MfaProcedureRepository {

    /**
     * Create OTP challenge
     *
     * @return Challenge ID
     */
    UUID createOtpChallenge(
            String userId,
            UUID sessionId,
            String purpose,
            String channel,
            String destination,
            byte[] codeHash,
            Integer ttlSeconds,
            String reference
    );

    /**
     * Verify OTP for login (v2.3)
     * Application-configured parameters
     */
    void verifyOtpForLogin(
            String userId,
            UUID sessionId,
            UUID challengeId,
            byte[] codeHash,
            Boolean trustThisDevice,
            Integer trustTtlDays,
            String deviceType,
            String deviceName,
            Integer maxTrustedDevices,
            Boolean sendEmailNotification
    );

    /**
     * Verify TOTP for login (v2.3)
     * Application-configured parameters
     */
    void verifyTotpForLogin(
            String userId,
            UUID sessionId,
            Boolean totpOk,
            Boolean trustThisDevice,
            Integer trustTtlDays,
            String deviceType,
            String deviceName,
            Integer maxTrustedDevices,
            Boolean sendEmailNotification
    );

    /**
     * Process incoming WhatsApp OTP
     * Auto-verify feature
     */
    void processIncomingWhatsAppOtp(
            String fromNumber,
            String messageText,
            String messageId
    );

    boolean verifyOtpChallenge(UUID challengeId, byte[] codeHash);

    /**
     * Complete MFA login and store tokens
     */
    UUID completeMfaLogin(
            String userId,
            UUID sessionId,
            String jwtKid,
            String jwtJti,
            byte[] refreshTokenHash,
            LocalDateTime refreshTokenExp,
            String ipAddress,
            String userAgent,
            String terminalId,
            Integer serverNo
    );
}
