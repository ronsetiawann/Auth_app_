package com.strade.auth_app.service;

import com.strade.auth_app.constant.AppConstants;
import com.strade.auth_app.constant.EventTypes;
import com.strade.auth_app.dto.request.TransactionOtpSendRequest;
import com.strade.auth_app.dto.request.TransactionOtpVerifyRequest;
import com.strade.auth_app.dto.response.TransactionOtpResponse;
import com.strade.auth_app.exception.AuthException;
import com.strade.auth_app.exception.ErrorCode;
import com.strade.auth_app.repository.jpa.OtpChallengeRepository;
import com.strade.auth_app.repository.procedure.MfaProcedureRepository;
import com.strade.auth_app.security.SecurityContextUtil;
import com.strade.auth_app.service.cache.RateLimitCacheService;
import com.strade.auth_app.service.notification.MekariWhatsAppService;
import com.strade.auth_app.util.HashUtil;
import com.strade.auth_app.util.RandomUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

/**
 * Transaction OTP Service - Stock Trading
 * WhatsApp Only via Mekari Qontak
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class TransactionOtpService {

    private final MfaProcedureRepository mfaProcedureRepository;
    private final MekariWhatsAppService mekariWhatsAppService;
    private final UserService userService;
    private final EventLogService eventLogService;
    private final RateLimitCacheService rateLimitCacheService;
    private final OtpChallengeRepository otpChallengeRepository;

    @Value("${app.security.transaction-otp.ttl-seconds:180}")
    private Integer otpTtlSeconds;

    @Value("${app.security.transaction-otp.max-attempts:3}")
    private Integer maxAttempts;

    @Value("${app.security.transaction-otp.use-random-code:false}")
    private Boolean useRandomCode;

    @Value("${app.security.transaction-otp.skip-send-if-no-phone:true}")
    private Boolean skipSendIfNoPhone;

    /**
     * Send transaction OTP via WhatsApp
     */
    @Transactional
    public TransactionOtpResponse sendTransactionOtp(TransactionOtpSendRequest request) {
        String userId = request.getUserId();
        String clientId = request.getClientId();

        log.info("Sending transaction OTP: userId={}, purpose={}, reference={}",
                userId, request.getPurpose(), request.getReference());

        // Rate limit: max 3 requests per 5 minutes
        rateLimitCacheService.checkAndIncrement(
                "transaction_otp_send",
                userId,
                3,
                300
        );

        // Get user phone & name
        String phoneNumber = null;
        String userName = null;
        boolean shouldSendWhatsApp = true;

        try {
            phoneNumber = userService.getUserMobilePhoneByClientId(clientId);
            userName = userService.getUserDisplayNameByClientId(clientId);
        } catch (AuthException e) {
            if (skipSendIfNoPhone) {
                log.warn("Phone number not found for clientId={}, skipping WhatsApp send", clientId);
                shouldSendWhatsApp = false;
                // Set default values untuk challenge creation
                phoneNumber = "N/A";
                userName = "Unknown User";
            } else {
                throw e; // Re-throw if not skipping
            }
        }

        // Generate OTP based on configuration
        String otpCode;
        byte[] codeHash;

        if (useRandomCode) {
            otpCode = RandomUtil.generateNumericOtp(AppConstants.DEFAULT_OTP_LENGTH);
            codeHash = HashUtil.sha256WithSalt(otpCode);
            log.debug("Using random OTP code with SHA256 hash");
        } else {
            otpCode = "999999";
            codeHash = otpCode.getBytes();
            log.debug("Using fixed OTP code: 999999");
        }

        // Create OTP challenge
        String purpose = "TRANSACTION_" + request.getPurpose().toUpperCase();
        UUID challengeId = mfaProcedureRepository.createOtpChallenge(
                userId,
                null,  // No session
                purpose,
                "whatsapp",
                phoneNumber,
                codeHash,
                otpTtlSeconds,
                request.getReference()
        );

        log.info("Transaction OTP challenge created: challengeId={}", challengeId);

        // Send via WhatsApp only if phone number is available
        if (shouldSendWhatsApp) {
            try {
                mekariWhatsAppService.sendTransactionOtp(
                        userId,
                        phoneNumber,
                        userName,
                        otpCode,
                        request
                );
                log.info("Transaction OTP sent successfully via WhatsApp: challengeId={}", challengeId);
            } catch (Exception e) {
                log.error("Failed to send WhatsApp OTP: challengeId={}, error={}", challengeId, e.getMessage());
                // Continue execution, challenge sudah dibuat
            }
        } else {
            log.info("WhatsApp send skipped due to missing phone number: challengeId={}", challengeId);
        }

        // Log event
        eventLogService.logEvent(
                userId,
                null,
                EventTypes.OTP_SENT,
                "Transaction OTP sent: " + request.getPurpose() +
                        (shouldSendWhatsApp ? " (WhatsApp)" : " (Phone not available)")
        );

        return TransactionOtpResponse.builder()
                .challengeId(challengeId)
                .expiresIn(otpTtlSeconds)
                .attemptsRemaining(maxAttempts)
                .message(shouldSendWhatsApp ? "OTP sent to WhatsApp" : "OTP challenge created (WhatsApp not sent)")
                .build();
    }

    /**
     * Verify transaction OTP
     */
    @Transactional
    public void verifyTransactionOtp(TransactionOtpVerifyRequest request) {
        String userId = userService.getUserIdByChallengeId(String.valueOf(request.getChallengeId()));

        log.info("Verifying transaction OTP: challengeId={}", request.getChallengeId());

        // Rate limit
        rateLimitCacheService.checkAndIncrement(
                "transaction_otp_verify",
                request.getChallengeId().toString(),
                maxAttempts,
                otpTtlSeconds
        );

        // Generate code hash based on configuration
        byte[] codeHash;
        if (useRandomCode) {
            codeHash = HashUtil.sha256WithSalt(request.getCode());
            log.debug("Verifying with SHA256 hashed code");
        } else {
            codeHash = request.getCode().getBytes();
            log.debug("Verifying with plain code bytes");
        }

        // Verify OTP
        boolean isValid = mfaProcedureRepository.verifyOtpChallenge(
                request.getChallengeId(),
                codeHash
        );

        if (!isValid) {
            log.warn("Invalid transaction OTP: challengeId={}", request.getChallengeId());
            eventLogService.logEvent(
                    userId,
                    null,
                    "OTP_VERIFY_FAILED",
                    "Transaction OTP verification failed"
            );
            throw new AuthException(ErrorCode.OTP_INVALID, "Invalid or expired OTP");
        }

        // Success
        rateLimitCacheService.reset("transaction_otp_verify", request.getChallengeId().toString());
        eventLogService.logEvent(
                userId,
                null,
                EventTypes.OTP_VERIFIED,
                "Transaction OTP verified"
        );

        log.info("Transaction OTP verified successfully: challengeId={}", request.getChallengeId());
    }

    /**
     * Mask phone number
     */
    private String maskPhoneNumber(String phone) {
        if (phone == null || phone.length() < 8) {
            return "***";
        }
        return "+62***" + phone.substring(phone.length() - 4);
    }
}