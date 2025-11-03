package com.strade.auth_app.service;

import com.strade.auth_app.constant.AppConstants;
import com.strade.auth_app.dto.request.OtpSendRequest;
import com.strade.auth_app.dto.response.OtpChallengeResponse;
import com.strade.auth_app.entity.Session;
import com.strade.auth_app.exception.AuthException;
import com.strade.auth_app.exception.ErrorCode;
import com.strade.auth_app.repository.jpa.SessionRepository;
import com.strade.auth_app.repository.procedure.MfaProcedureRepository;
import com.strade.auth_app.service.notification.EmailService;
import com.strade.auth_app.service.notification.MekariWhatsAppService;
import com.strade.auth_app.service.notification.SmsService;
import com.strade.auth_app.util.HashUtil;
import com.strade.auth_app.util.RandomUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

/**
 * OTP service - handles OTP generation and verification
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class OtpService {

    private final SessionRepository sessionRepository;
    private final MfaProcedureRepository mfaProcedureRepository;
    private final MekariWhatsAppService mekariWhatsAppService;
    private final EmailService emailService;
    private final SmsService smsService;
    private final UserService userService;

    @Value("${app.security.mfa.otp.ttl-seconds:300}")
    private Integer otpTtlSeconds;

    /**
     * Send OTP via specified channel
     */
    @Transactional
    public OtpChallengeResponse sendOtp(OtpSendRequest request) {
        log.info("Sending OTP for sessionId: {}, channel: {}",
                request.getSessionId(), request.getChannel());

        // 1. Validate session
        Session session = sessionRepository.findBySessionId(request.getSessionId())
                .orElseThrow(() -> new AuthException(
                        ErrorCode.SESSION_NOT_FOUND,
                        "Session not found"
                ));

        if (session.getStatus() != AppConstants.SESSION_STATUS_PENDING) {
            throw new AuthException(
                    ErrorCode.SESSION_INACTIVE,
                    "Session is not in pending MFA state"
            );
        }

        String userId = session.getUserId();

        // 2. Determine destination (phone/email) ✅ Updated
        String destination = determineDestination(request, userId);

        // 3. Get user display name ✅ Added
        String userName = userService.getUserDisplayName(userId);

        // 4. Generate OTP code
        String otpCode = RandomUtil.generateNumericOtp(AppConstants.DEFAULT_OTP_LENGTH);
        byte[] codeHash = HashUtil.sha256WithSalt(otpCode);

        log.debug("Generated OTP code for user: {} (hash stored in DB)", userId);

        // 5. Create OTP challenge in database (via stored procedure)
        UUID challengeId = mfaProcedureRepository.createOtpChallenge(
                userId,
                request.getSessionId(),
                request.getPurpose(),
                request.getChannel(),
                destination,
                codeHash,
                otpTtlSeconds,
                null
        );

        log.info("OTP challenge created: {}", challengeId);

        // 6. Send OTP via channel ✅ Updated with userName
        sendOtpViaChannel(request.getChannel(), userId, destination, userName, otpCode);

        // 7. Build response
        return OtpChallengeResponse.builder()
                .challengeId(challengeId)
                .expiresIn(otpTtlSeconds)
                .attemptsRemaining(AppConstants.DEFAULT_OTP_MAX_ATTEMPTS)
                .maskedDestination(maskDestination(destination, request.getChannel()))
                .message("OTP sent successfully to " + request.getChannel())
                .build();
    }

    /**
     * Determine destination based on channel ✅ Updated
     */
    private String determineDestination(OtpSendRequest request, String userId) {
        // If destination explicitly provided, use it
        if (request.getDestination() != null && !request.getDestination().isEmpty()) {
            return request.getDestination();
        }

        // Otherwise, get from user profile based on channel
        return switch (request.getChannel().toLowerCase()) {
            case "sms", "whatsapp" -> userService.getUserMobilePhone(userId);
            case "email" -> userService.getUserEmail(userId);
            default -> throw new AuthException(
                    ErrorCode.INVALID_REQUEST,
                    "Invalid channel: " + request.getChannel()
            );
        };
    }

    /**
     * Send OTP via specified channel ✅ Updated signature
     */
    private void sendOtpViaChannel(
            String channel,
            String userId,
            String destination,
            String userName,  // ✅ Added parameter
            String otpCode
    ) {
        try {
            switch (channel.toLowerCase()) {
                case "whatsapp" ->
                        mekariWhatsAppService.sendOtp(userId, destination, userName, otpCode);
                case "sms" ->
                        smsService.sendOtp(userId, destination, userName, otpCode);
                case "email" ->
                        emailService.sendOtp(userId, destination, userName, otpCode);
                default -> throw new AuthException(
                        ErrorCode.INVALID_REQUEST,
                        "Invalid channel: " + channel
                );
            }
        } catch (AuthException e) {
            throw e;
        } catch (Exception e) {
            log.error("Failed to send OTP via {}", channel, e);
            throw new AuthException(
                    ErrorCode.NOTIFICATION_SEND_FAILED,
                    "Failed to send OTP",
                    e
            );
        }
    }

    /**
     * Mask destination for privacy
     */
    private String maskDestination(String destination, String channel) {
        if (destination == null || destination.isEmpty()) {
            return "***";
        }

        return switch (channel.toLowerCase()) {
            case "sms", "whatsapp" -> {
                // Mask phone: 628123456789 -> +62***6789
                if (destination.length() > 8) {
                    yield "+62***" + destination.substring(destination.length() - 4);
                }
                yield "***" + destination.substring(Math.max(0, destination.length() - 4));
            }
            case "email" -> {
                // Mask email: john.doe@example.com -> j***e@example.com
                int atIndex = destination.indexOf('@');
                if (atIndex > 2) {
                    yield destination.charAt(0) + "***" +
                            destination.charAt(atIndex - 1) +
                            destination.substring(atIndex);
                }
                yield "***@" + destination.substring(atIndex + 1);
            }
            default -> "***";
        };
    }
}