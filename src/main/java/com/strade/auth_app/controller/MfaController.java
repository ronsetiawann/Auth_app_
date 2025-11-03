package com.strade.auth_app.controller;

import com.strade.auth_app.config.properties.SecurityProperties;
import com.strade.auth_app.constant.AppConstants;
import com.strade.auth_app.dto.request.*;
import com.strade.auth_app.dto.response.*;
import com.strade.auth_app.entity.Session;
import com.strade.auth_app.exception.AuthException;
import com.strade.auth_app.exception.ErrorCode;
import com.strade.auth_app.repository.jpa.SessionRepository;
import com.strade.auth_app.security.SecurityContextUtil;
import com.strade.auth_app.service.MfaService;
import com.strade.auth_app.service.OtpService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

/**
 * Multi-Factor Authentication REST API Controller
 */
@RestController
@RequestMapping("/api/v1/mfa")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "MFA", description = "Multi-Factor Authentication APIs")
public class MfaController {

    private final MfaService mfaService;
    private final OtpService otpService;
    private final SecurityProperties securityProperties;
    private final SessionRepository sessionRepository;

    // ========================================
    // MFA Status
    // ========================================

    /**
     * Get MFA status
     * GET /api/v1/mfa/status
     */
    @GetMapping("/status")
    @Operation(summary = "Get MFA status", description = "Get current user's MFA configuration status")
    public ResponseEntity<ApiResponse<MfaStatusResponse>> getMfaStatus() {
        String userId = SecurityContextUtil.requireAuthentication().getUserId();

        log.debug("Get MFA status: userId={}", userId);

        MfaStatusResponse response = mfaService.getMfaStatus(userId);

        return ResponseEntity.ok(ApiResponse.success(response));
    }

    // ========================================
    // OTP APIs
    // ========================================

    /**
     * Send OTP
     * POST /api/v1/mfa/otp/send
     */
    @PostMapping("/otp/send")
    @Operation(summary = "Send OTP", description = "Send OTP via SMS, Email, or WhatsApp")
    public ResponseEntity<ApiResponse<OtpChallengeResponse>> sendOtp(
            @Valid @RequestBody OtpSendRequest request
    ) {
        log.info("Send OTP request: sessionId={}, channel={}",
                request.getSessionId(), request.getChannel());

        OtpChallengeResponse response = otpService.sendOtp(request);

        return ResponseEntity.ok(ApiResponse.success(response));
    }

    /**
     * Verify OTP
     * POST /api/v1/mfa/otp/verify
     */
    @PostMapping("/otp/verify")
    @Operation(summary = "Verify OTP", description = "Verify OTP code for login")
    public ResponseEntity<ApiResponse<MfaVerifyResponse>> verifyOtp(
            @Valid @RequestBody OtpVerifyRequest request
    ) {
        log.info("Verify OTP request: sessionId={}, challengeId={}",
                request.getSessionId(), request.getChallengeId());
        try {
            MfaVerifyResponse response = mfaService.verifyOtpForLogin(request);
            return ResponseEntity.ok(ApiResponse.success(response));
        } catch (Exception e) {
            log.error("OTP verify error", e);
            throw e;
        }
    }

    // ========================================
    // TOTP APIs
    // ========================================

    /**
     * Setup TOTP
     * POST /api/v1/mfa/totp/setup
     */
    @PostMapping("/totp/setup")
    @Operation(summary = "Setup TOTP", description = "Initialize TOTP setup for Google Authenticator")
    public ResponseEntity<ApiResponse<TotpSetupResponse>> setupTotp(
            @RequestBody(required = false) TotpSetupRequest request  // ✅ Use request body
    ) {
        boolean requiresAuth = securityProperties.getMfa().isTotpSetupRequiresAuth();

        String targetUserId;

        if (requiresAuth) {
            // Mode 1: Requires authentication
            targetUserId = SecurityContextUtil.requireAuthentication().getUserId();
            log.info("Setup TOTP (authenticated): userId={}", targetUserId);
        } else {
            // Mode 2: No auth required (during MFA flow)
            if (request == null || request.getUserId() == null || request.getSessionId() == null) {
                throw new AuthException(
                        ErrorCode.INVALID_REQUEST,
                        "userId and sessionId are required for TOTP setup"
                );
            }

            // Validate session is in MFA pending state
            Session session = sessionRepository.findBySessionId(request.getSessionId())
                    .orElseThrow(() -> new AuthException(
                            ErrorCode.SESSION_NOT_FOUND,
                            "Session not found"
                    ));

            if (session.getStatus() != AppConstants.SESSION_STATUS_PENDING || !session.getMfaRequired()) {
                throw new AuthException(
                        ErrorCode.INVALID_REQUEST,
                        "Session is not in MFA pending state"
                );
            }

            if (!session.getUserId().equals(request.getUserId())) {
                throw new AuthException(
                        ErrorCode.INVALID_REQUEST,
                        "UserId mismatch with session"
                );
            }

            targetUserId = request.getUserId();
            log.info("Setup TOTP (no-auth mode): userId={}, sessionId={}",
                    targetUserId, request.getSessionId());
        }

        TotpSetupResponse response = mfaService.setupTotp(targetUserId);
        return ResponseEntity.ok(ApiResponse.success(response));
    }

    /**
     * Activate TOTP
     * POST /api/v1/mfa/totp/activate
     */
    @PostMapping("/totp/activate")
    @Operation(summary = "Activate TOTP", description = "Activate TOTP by verifying first code")
    public ResponseEntity<ApiResponse<Void>> activateTotp(
            @Valid @RequestBody TotpActivateRequest request
    ) {
        boolean requiresAuth = securityProperties.getMfa().isTotpSetupRequiresAuth();

        String targetUserId;

        if (requiresAuth) {
            targetUserId = SecurityContextUtil.requireAuthentication().getUserId();
            log.info("Activate TOTP (authenticated): userId={}", targetUserId);
        } else {
            if (request.getUserId() == null || request.getSessionId() == null) {
                throw new AuthException(
                        ErrorCode.INVALID_REQUEST,
                        "userId and sessionId are required for TOTP activation"
                );
            }

            Session session = sessionRepository.findBySessionId(request.getSessionId())
                    .orElseThrow(() -> new AuthException(
                            ErrorCode.SESSION_NOT_FOUND,
                            "Session not found"
                    ));

            if (!session.getUserId().equals(request.getUserId())) {
                throw new AuthException(
                        ErrorCode.INVALID_REQUEST,
                        "UserId mismatch with session"
                );
            }

            targetUserId = request.getUserId();
            log.info("Activate TOTP (no-auth mode): userId={}, sessionId={}",
                    targetUserId, request.getSessionId());
        }

        mfaService.activateTotp(targetUserId, request);
        return ResponseEntity.ok(ApiResponse.success(null));
    }


    /**
     * Verify TOTP for login
     * POST /api/v1/mfa/totp/verify
     */
    @PostMapping("/totp/verify")
    @Operation(summary = "Verify TOTP", description = "Verify TOTP code for login")
    public ResponseEntity<ApiResponse<Void>> verifyTotp(
            @Valid @RequestBody TotpVerifyRequest request
    ) {
        log.info("Verify TOTP: sessionId={}", request.getSessionId());

        mfaService.verifyTotpForLogin(request);

        return ResponseEntity.ok(ApiResponse.success(null));
    }

    /**
     * Disable TOTP
     * POST /api/v1/mfa/totp/disable
     */
    @PostMapping("/totp/disable")
    @Operation(summary = "Disable TOTP", description = "Disable TOTP authentication")
    public ResponseEntity<ApiResponse<Void>> disableTotp() {
        String userId = SecurityContextUtil.requireAuthentication().getUserId();

        log.info("Disable TOTP: userId={}", userId);

        mfaService.disableTotp(userId);

        return ResponseEntity.ok(ApiResponse.success(null));
    }

    // ========================================
    // Backup Codes APIs
    // ========================================

    /**
     * Regenerate backup codes
     * POST /api/v1/mfa/backup-codes/regenerate
     */
    @PostMapping("/backup-codes/regenerate")
    @Operation(summary = "Regenerate backup codes", description = "Generate new backup codes")
    public ResponseEntity<ApiResponse<List<String>>> regenerateBackupCodes() {
        String userId = SecurityContextUtil.requireAuthentication().getUserId();

        log.info("Regenerate backup codes: userId={}", userId);

        List<String> backupCodes = mfaService.regenerateBackupCodes(userId);

        return ResponseEntity.ok(ApiResponse.success(backupCodes));
    }
}
