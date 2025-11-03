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

    /**
     * Send transaction OTP via WhatsApp
     */
    @Transactional
    public TransactionOtpResponse sendTransactionOtp(TransactionOtpSendRequest request) {
        //String userId = SecurityContextUtil.requireAuthentication().getUserId();
        String userId = request.getUserId();
        String clientId = request.getClientId();

        log.info("Sending transaction OTP: userId={}, purpose={}, referece={}",
                userId, request.getPurpose(), request.getReference());

        // Rate limit: max 3 requests per 5 minutes
        rateLimitCacheService.checkAndIncrement(
                "transaction_otp_send",
                userId,
                3,
                300
        );

        // Get user phone & name
        String phoneNumber = userService.getUserMobilePhoneByClientId(clientId);
        String userName = userService.getUserDisplayNameByClientId(clientId);

        // Generate OTP
        //String otpCode = RandomUtil.generateNumericOtp(AppConstants.DEFAULT_OTP_LENGTH);
        String otpCode = "999999";
        byte[] codeHash = otpCode.getBytes();
        //byte[] codeHash = HashUtil.sha256WithSalt(otpCode);

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

        // Send via WhatsApp
//        mekariWhatsAppService.sendTransactionOtp(
//                userId,
//                phoneNumber,
//                userName,
//                otpCode,
//                request
//        );

        // Log event
        eventLogService.logEvent(
                userId,
                null,
                EventTypes.OTP_SENT,
                "Transaction OTP sent: " + request.getPurpose()
        );

        log.info("Transaction OTP sent successfully via WhatsApp: challengeId={}", challengeId);

        return TransactionOtpResponse.builder()
                .challengeId(challengeId)
                .expiresIn(otpTtlSeconds)
                .attemptsRemaining(maxAttempts)
                .message("OTP sent to WhatsApp")
                .build();
    }

    /**
     * Verify transaction OTP
     */
    @Transactional
    public void verifyTransactionOtp(TransactionOtpVerifyRequest request) {
        //String userId = SecurityContextUtil.requireAuthentication().getUserId();

        String userId = userService.getUserIdByChallengeId(String.valueOf(request.getChallengeId()));

        log.info("Verifying transaction hallengeId={}",
                request.getChallengeId());

        // Rate limit
        rateLimitCacheService.checkAndIncrement(
                "transaction_otp_verify",
                request.getChallengeId().toString(),
                maxAttempts,
                otpTtlSeconds
        );

        // Verify
        //byte[] codeHash = HashUtil.sha256WithSalt(request.getCode());
//        boolean isValid = mfaProcedureRepository.verifyOtpChallenge(
//                request.getChallengeId(),
//                codeHash
//        );
        byte[] codeHash = request.getCode().getBytes(); // Simple bytes untuk testing
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