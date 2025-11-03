package com.strade.auth_app.constant;
/**
 * Redis cache key constants
 */
public final class CacheKeys {

    private CacheKeys() {
        throw new IllegalStateException("Utility class");
    }

    private static final String PREFIX = "auth:";

    // Session cache
    public static final String SESSION_PREFIX = PREFIX + "session:";
    public static String session(String sessionId) {
        return SESSION_PREFIX + sessionId;
    }

    // User MFA config cache
    public static final String USER_MFA_PREFIX = PREFIX + "mfa:";
    public static String userMfa(String userId) {
        return USER_MFA_PREFIX + userId;
    }

    // Trusted device cache
    public static final String TRUSTED_DEVICE_PREFIX = PREFIX + "trusted:";
    public static String trustedDevice(String userId, String deviceId, String channel) {
        return TRUSTED_DEVICE_PREFIX + userId + ":" + deviceId + ":" +
                (channel != null ? channel : "");
    }

    // JWT public key cache
    public static final String JWT_PUBLIC_KEY_PREFIX = PREFIX + "key:";
    public static String jwtPublicKey(String kid) {
        return JWT_PUBLIC_KEY_PREFIX + kid;
    }

    // Active key cache
    public static final String ACTIVE_KEY = PREFIX + "key:active";

    // Access token denylist
    public static final String DENY_JTI_PREFIX = PREFIX + "deny:";
    public static String denyJti(String jti) {
        return DENY_JTI_PREFIX + jti;
    }

    // Rate limit cache
    public static final String RATE_LIMIT_PREFIX = PREFIX + "ratelimit:";
    public static String rateLimit(String type, String identifier) {
        return RATE_LIMIT_PREFIX + type + ":" + identifier;
    }

    // Refresh token cache (for reuse detection)
    public static final String REFRESH_TOKEN_PREFIX = PREFIX + "refresh:";
    public static String refreshToken(String tokenHash) {
        return REFRESH_TOKEN_PREFIX + tokenHash;
    }
}
