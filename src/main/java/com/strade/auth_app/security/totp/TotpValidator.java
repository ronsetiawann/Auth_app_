package com.strade.auth_app.security.totp;

import com.strade.auth_app.config.properties.SecurityProperties;
import com.strade.auth_app.exception.ErrorCode;
import com.strade.auth_app.exception.MfaException;
import com.strade.auth_app.util.DateTimeUtil;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorConfig;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import com.warrenstrange.googleauth.HmacHashFunction;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.concurrent.TimeUnit;

/**
 * TOTP (Time-based One-Time Password) validator
 * Compatible with Google Authenticator, Authy, etc.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class TotpValidator {

    private final SecurityProperties securityProperties;

    /**
     * Generate TOTP secret
     *
     * @return Base32-encoded secret
     */
    public String generateSecret() {
        GoogleAuthenticator gAuth = createAuthenticator();
        GoogleAuthenticatorKey key = gAuth.createCredentials();
        String secret = key.getKey();

        log.debug("Generated TOTP secret (length: {})", secret.length());
        return secret;
    }

    /**
     * Validate TOTP code
     *
     * @param secret Base32-encoded secret
     * @param code User-provided code
     * @param lastUsedTimeStep Last used time step (for replay prevention)
     * @return Current time step if valid
     * @throws MfaException if invalid
     */
    public long validateCode(String secret, String code, Long lastUsedTimeStep) {
        if (secret == null || secret.isEmpty()) {
            throw new MfaException(ErrorCode.TOTP_NOT_SETUP, "TOTP secret not configured");
        }

        if (code == null || code.length() != securityProperties.getMfa().getTotp().getDigits()) {
            throw new MfaException(ErrorCode.TOTP_INVALID, "Invalid TOTP code format");
        }

        try {
            int codeInt = Integer.parseInt(code);

            // Get current time step
            long currentTimeStep = getCurrentTimeStep();

            // Check for replay attack
            if (lastUsedTimeStep != null && currentTimeStep <= lastUsedTimeStep) {
                log.warn("TOTP replay attack detected. Current: {}, Last used: {}",
                        currentTimeStep, lastUsedTimeStep);
                throw new MfaException(ErrorCode.TOTP_REPLAY_DETECTED,
                        "TOTP code already used or clock skew detected");
            }

            // Validate with window
            GoogleAuthenticator gAuth = createAuthenticator();
            boolean isValid = gAuth.authorize(secret, codeInt);

            if (!isValid) {
                log.debug("TOTP validation failed for time step: {}", currentTimeStep);
                throw new MfaException(ErrorCode.TOTP_INVALID, "Invalid TOTP code");
            }

            log.debug("TOTP validated successfully at time step: {}", currentTimeStep);
            return currentTimeStep;

        } catch (NumberFormatException e) {
            throw new MfaException(ErrorCode.TOTP_INVALID, "TOTP code must be numeric");
        }
    }

    /**
     * Generate QR code URI for TOTP setup
     *
     * @param secret Base32-encoded secret
     * @param accountName User's account name (typically email or username)
     * @return otpauth:// URI
     */
    public String generateQrCodeUri(String secret, String accountName) {
        String issuer = securityProperties.getMfa().getTotp().getIssuer();
        int digits = securityProperties.getMfa().getTotp().getDigits();
        int period = securityProperties.getMfa().getTotp().getPeriodSeconds();
        String algorithm = securityProperties.getMfa().getTotp().getAlgorithm();

        return String.format(
                "otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=%s&digits=%d&period=%d",
                issuer,
                accountName,
                secret,
                issuer,
                algorithm,
                digits,
                period
        );
    }

    /**
     * Get current TOTP time step
     *
     * @return Current time step
     */
    public long getCurrentTimeStep() {
        int periodSeconds = securityProperties.getMfa().getTotp().getPeriodSeconds();
        return DateTimeUtil.getTotpTimeStep(periodSeconds);
    }

    /**
     * Get seconds remaining in current time window
     *
     * @return Seconds until code changes
     */
    public long getSecondsRemaining() {
        int periodSeconds = securityProperties.getMfa().getTotp().getPeriodSeconds();
        long currentSeconds = System.currentTimeMillis() / 1000;
        long secondsInCurrentWindow = currentSeconds % periodSeconds;
        return periodSeconds - secondsInCurrentWindow;
    }

    /**
     * Create configured GoogleAuthenticator instance
     */
    private GoogleAuthenticator createAuthenticator() {
        SecurityProperties.MfaProperties.TotpConfig config =
                securityProperties.getMfa().getTotp();

        GoogleAuthenticatorConfig.GoogleAuthenticatorConfigBuilder configBuilder =
                new GoogleAuthenticatorConfig.GoogleAuthenticatorConfigBuilder()
                        .setCodeDigits(config.getDigits())
                        .setTimeStepSizeInMillis(
                                TimeUnit.SECONDS.toMillis(config.getPeriodSeconds())
                        )
                        .setWindowSize(config.getWindow());

        // Set hash function based on algorithm
        HmacHashFunction hashFunction = switch (config.getAlgorithm().toUpperCase()) {
            case "SHA256" -> HmacHashFunction.HmacSHA256;
            case "SHA512" -> HmacHashFunction.HmacSHA512;
            default -> HmacHashFunction.HmacSHA1;
        };

        configBuilder.setHmacHashFunction(hashFunction);

        return new GoogleAuthenticator(configBuilder.build());
    }
}
