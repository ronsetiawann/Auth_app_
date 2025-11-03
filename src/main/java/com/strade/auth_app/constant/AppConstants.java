package com.strade.auth_app.constant;

/**
 * Application-wide constants
 */
public final class AppConstants {

    private AppConstants() {
        throw new IllegalStateException("Utility class");
    }

    // Application Info
    public static final String APP_NAME = "STRADE Auth Service";
    public static final String APP_VERSION = "1.0.0";

    // Security
    public static final String SALT = "auth_salt_2024";
    public static final String JWT_HEADER = "Authorization";
    public static final String JWT_PREFIX = "Bearer ";

    // Channels (from ChannelVersion table)
    public static final String CHANNEL_ANDROID = "AD";
    public static final String CHANNEL_IOS = "OS";
    public static final String CHANNEL_BLACKBERRY = "BB";
    public static final String CHANNEL_WEB = "WB";
    public static final String CHANNEL_OTHER_APP = "OA";
    public static final String CHANNEL_APP_MOBILE = "AM";
    public static final String CHANNEL_OTHER_TABLET = "OT";
    public static final String CHANNEL_RICH_TERMINAL = "RT";

    // Legacy channel names (for backward compatibility)
    public static final String CHANNEL_LEGACY_IDXMOBILE = "IDXMOBILE";
    public static final String CHANNEL_LEGACY_WEB = "WEB";
    public static final String CHANNEL_LEGACY_MOBILE = "MOBILE";

    // Session Status
    public static final byte SESSION_STATUS_PENDING = 0;
    public static final byte SESSION_STATUS_ACTIVE = 1;
    public static final byte SESSION_STATUS_REVOKED = 2;
    public static final byte SESSION_STATUS_EXPIRED = 3;

    // OTP Status
    public static final byte OTP_STATUS_PENDING = 0;
    public static final byte OTP_STATUS_USED = 1;
    public static final byte OTP_STATUS_EXPIRED = 2;
    public static final byte OTP_STATUS_MAX_ATTEMPTS = 3;

    // TOTP Status
    public static final byte TOTP_STATUS_INACTIVE = 0;
    public static final byte TOTP_STATUS_ACTIVE = 1;
    public static final byte TOTP_STATUS_SUSPENDED = 2;

    // Notification Status
    public static final byte NOTIFICATION_STATUS_PENDING = 0;
    public static final byte NOTIFICATION_STATUS_SENT = 1;
    public static final byte NOTIFICATION_STATUS_FAILED = 2;

    // Default Values
    public static final int DEFAULT_OTP_LENGTH = 6;
    public static final int DEFAULT_OTP_TTL_SECONDS = 300;
    public static final int DEFAULT_OTP_MAX_ATTEMPTS = 5;
    public static final int DEFAULT_TOTP_DIGITS = 6;
    public static final int DEFAULT_TOTP_PERIOD_SECONDS = 30;
    public static final int DEFAULT_TRUST_TTL_DAYS = 90;
    public static final int DEFAULT_MAX_TRUSTED_DEVICES = 3;
}