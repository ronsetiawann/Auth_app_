package com.strade.auth_app.config.properties;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Security configuration properties
 */
@Getter
@Setter
@Component
@ConfigurationProperties(prefix = "app.security")
public class SecurityProperties {

    private Integer maxLoginRetry = 5;
    private String encryptionKey;

    private MfaProperties mfa = new MfaProperties();
    private RateLimitProperties rateLimit = new RateLimitProperties();

    /**
     * MFA configuration
     */
    @Getter
    @Setter
    public static class MfaProperties {
        private boolean enforced = true;

        // ✅ NEW: Available methods configuration
        private List<String> availableMethods = List.of("OTP_EMAIL", "OTP_SMS");

        // ✅ NEW: TOTP setup mode
        private boolean totpSetupRequiresAuth = false;

        private OtpConfig otp = new OtpConfig();
        private TotpConfig totp = new TotpConfig();
        private TrustedDeviceConfig trustedDevice = new TrustedDeviceConfig();
        private BackupCodesConfig backupCodes = new BackupCodesConfig();

        /**
         * Check if TOTP is enabled in configuration
         */
        public boolean isTotpEnabled() {
            return availableMethods.stream()
                    .anyMatch(m -> "TOTP".equalsIgnoreCase(m));
        }

        /**
         * Check if OTP method is enabled
         */
        public boolean isOtpMethodEnabled(String method) {
            return availableMethods.stream()
                    .anyMatch(m -> m.equalsIgnoreCase(method));
        }

        /**
         * Get normalized available methods (lowercase, with otp_ prefix)
         */
        public Set<String> getNormalizedAvailableMethods() {
            return availableMethods.stream()
                    .map(String::toUpperCase)
                    .map(m -> {
                        if ("TOTP".equals(m)) return "totp";
                        if ("OTP_SMS".equals(m)) return "otp_sms";
                        if ("OTP_EMAIL".equals(m)) return "otp_email";
                        if ("OTP_WHATSAPP".equals(m)) return "otp_whatsapp";
                        return m.toLowerCase();
                    })
                    .collect(Collectors.toSet());
        }

        @Getter
        @Setter
        public static class OtpConfig {
            private Integer length = 6;
            private Integer ttlSeconds = 300;
            private Integer maxAttempts = 5;
        }

        @Getter
        @Setter
        public static class TotpConfig {
            private String issuer = "STRADE";
            private Integer digits = 6;
            private Integer periodSeconds = 30;
            private String algorithm = "SHA1";
            private Integer window = 1;
        }

        @Getter
        @Setter
        public static class TrustedDeviceConfig {
            private Integer ttlDays = 90;
            private Integer maxDevices = 3;
            private boolean sendEmailNotification = true;
        }

        @Getter
        @Setter
        public static class BackupCodesConfig {
            private Integer count = 10;
        }
    }

    /**
     * Rate limit configuration
     */
    @Getter
    @Setter
    public static class RateLimitProperties {
        private LoginRateLimit login = new LoginRateLimit();
        private OtpRateLimit otp = new OtpRateLimit();
        private TotpRateLimit totp = new TotpRateLimit();

        @Getter
        @Setter
        public static class LoginRateLimit {
            private Integer maxAttempts = 5;
            private Integer windowSeconds = 300;
        }

        @Getter
        @Setter
        public static class OtpRateLimit {
            private Integer maxRequests = 3;
            private Integer windowSeconds = 300;
        }

        @Getter
        @Setter
        public static class TotpRateLimit {
            private Integer maxAttempts = 5;
            private Integer windowSeconds = 300;
        }
    }
}