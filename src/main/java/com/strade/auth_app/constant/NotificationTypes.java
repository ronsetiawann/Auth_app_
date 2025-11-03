package com.strade.auth_app.constant;

/**
 * Notification type constants
 */
public final class NotificationTypes {

    private NotificationTypes() {
        throw new IllegalStateException("Utility class");
    }

    // OTP Notifications
    public static final String OTP_LOGIN_2FA = "OTP_LOGIN_2FA";
    public static final String OTP_TRUST_DEVICE = "OTP_TRUST_DEVICE";
    public static final String OTP_PASSWORD_RESET = "OTP_PASSWORD_RESET";

    // Device Notifications
    public static final String TRUSTED_DEVICE_ADDED = "TRUSTED_DEVICE_ADDED";
    public static final String TRUSTED_DEVICE_REMOVED = "TRUSTED_DEVICE_REMOVED";
    public static final String ALL_TRUSTED_DEVICES_REMOVED = "ALL_TRUSTED_DEVICES_REMOVED";

    // Security Alerts
    public static final String SECURITY_ALERT_REFRESH_REUSE = "SECURITY_ALERT_REFRESH_REUSE";
    public static final String SECURITY_ALERT_MULTIPLE_FAILURES = "SECURITY_ALERT_MULTIPLE_FAILURES";
    public static final String SECURITY_ALERT_MULTIPLE_SESSIONS = "SECURITY_ALERT_MULTIPLE_SESSIONS";
    public static final String SECURITY_ALERT_TOKEN_REUSE = "SECURITY_ALERT_TOKEN_REUSE";

    // Login Notifications
    public static final String LOGIN_SUCCESS = "LOGIN_SUCCESS";
    public static final String LOGIN_FAILED = "LOGIN_FAILED";
    public static final String ALL_SESSIONS_REVOKED = "ALL_SESSIONS_REVOKED";

    // MFA Notifications
    public static final String MFA_ENABLED = "MFA_ENABLED";
    public static final String MFA_DISABLED = "MFA_DISABLED";

    // Password Notifications
    public static final String PASSWORD_CHANGED = "PASSWORD_CHANGED";
}
