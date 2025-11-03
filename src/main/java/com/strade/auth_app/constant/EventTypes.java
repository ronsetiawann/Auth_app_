package com.strade.auth_app.constant;
/**
 * Authentication event type constants
 */
public final class EventTypes {

    private EventTypes() {
        throw new IllegalStateException("Utility class");
    }

    // Authentication Events
    public static final String LOGIN_SUCCESS = "LOGIN_SUCCESS";
    public static final String LOGIN_FAILED = "LOGIN_FAILED";
    public static final String LOGOUT = "LOGOUT";
    public static final String LOGOUT_ALL = "USER_LOGOUT_ALL";

    // MFA Events
    public static final String MFA_REQUIRED = "MFA_REQUIRED";
    public static final String OTP_SENT = "OTP_SENT";
    public static final String OTP_VERIFIED = "OTP_VERIFIED";
    public static final String TOTP_VERIFIED = "TOTP_VERIFIED";
    public static final String TOTP_ENABLED = "MFA_ENABLED";
    public static final String TOTP_DISABLED = "MFA_DISABLED";
    public static final String MFA_COMPLETED = "MFA_COMPLETED";

    // Token Events
    public static final String REFRESH_ROTATED = "REFRESH_ROTATED";
    public static final String REFRESH_REUSE_DETECTED = "REFRESH_REUSE_DETECTED";
    public static final String ACCESS_TOKEN_REVOKED = "ACCESS_TOKEN_REVOKED";

    // Session Events
    public static final String SESSION_CREATED = "SESSION_CREATED";
    public static final String SESSION_REVOKED = "SESSION_REVOKED";

    // Device Events
    public static final String TRUSTED_DEVICE_ADDED = "TRUSTED_DEVICE_ADDED";
    public static final String TRUSTED_DEVICE_REMOVED = "TRUSTED_DEVICE_REMOVED";
    public static final String ALL_TRUSTED_DEVICES_REMOVED = "ALL_TRUSTED_DEVICES_REMOVED";
    public static final String TRUST_DEVICE_CONFIRMED = "TRUST_DEVICE_CONFIRMED";
    public static final String SECURITY_ALERT_MULTIPLE_FAILURES = "SECURITY_ALERT_MULTIPLE_FAILURES";

    // System Events
    public static final String SECURITY_MONITOR_TICK = "SECURITY_MONITOR_TICK";
    public static final String CRON_CLEANUP = "CRON_CLEANUP";
}
