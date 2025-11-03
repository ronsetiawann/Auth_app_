package com.strade.auth_app.util;

import java.util.Set;
import java.util.regex.Pattern;

/**
 * Utility class for input validation
 */
public final class ValidationUtil {

    private static final Pattern EMAIL_PATTERN =
            Pattern.compile("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$");

    private static final Pattern PHONE_PATTERN =
            Pattern.compile("^\\+?[1-9]\\d{1,14}$"); // E.164 format

    private static final Pattern UUID_PATTERN =
            Pattern.compile("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");

    private static final Pattern ALPHANUMERIC_PATTERN =
            Pattern.compile("^[A-Za-z0-9]+$");

    private static final Pattern NUMERIC_PATTERN =
            Pattern.compile("^[0-9]+$");

    /**
     * Valid channel codes based on ChannelVersion table
     */
    private static final Set<String> VALID_CHANNELS = Set.of(
            "AD",  // Android
            "OS",  // iOS
            "BB",  // BlackBerry
            "WB",  // Web
            "OA",  // Other App
            "AM",  // App Mobile
            "OT",  // Other/Tablet
            "RT"   // Rich Terminal/Desktop
    );

    /**
     * Legacy channel names for backward compatibility
     */
    private static final Set<String> LEGACY_CHANNELS = Set.of(
            "IDXMOBILE",  // Maps to AD/OS
            "WEB",        // Maps to WB
            "MOBILE"      // Maps to AD/OS
    );

    private ValidationUtil() {
        throw new IllegalStateException("Utility class");
    }

    /**
     * Validate email address
     */
    public static boolean isValidEmail(String email) {
        return email != null && EMAIL_PATTERN.matcher(email).matches();
    }

    /**
     * Validate phone number (E.164 format)
     */
    public static boolean isValidPhone(String phone) {
        return phone != null && PHONE_PATTERN.matcher(phone).matches();
    }

    /**
     * Validate UUID string
     */
    public static boolean isValidUuid(String uuid) {
        return uuid != null && UUID_PATTERN.matcher(uuid.toLowerCase()).matches();
    }

    /**
     * Validate OTP code
     */
    public static boolean isValidOtp(String otp, int expectedLength) {
        if (otp == null || otp.length() != expectedLength) {
            return false;
        }
        return NUMERIC_PATTERN.matcher(otp).matches();
    }

    /**
     * Validate TOTP code (6 digits)
     */
    public static boolean isValidTotp(String totp) {
        return isValidOtp(totp, 6);
    }

    /**
     * Validate alphanumeric string
     */
    public static boolean isAlphanumeric(String str) {
        return str != null && ALPHANUMERIC_PATTERN.matcher(str).matches();
    }

    /**
     * Validate string is not null or empty
     */
    public static boolean isNotEmpty(String str) {
        return str != null && !str.trim().isEmpty();
    }

    /**
     * Validate string length
     */
    public static boolean isValidLength(String str, int minLength, int maxLength) {
        if (str == null) {
            return false;
        }
        int length = str.length();
        return length >= minLength && length <= maxLength;
    }

    /**
     * Sanitize user input (remove dangerous characters)
     */
    public static String sanitize(String input) {
        if (input == null) {
            return null;
        }
        // Remove potential SQL injection characters
        return input.replaceAll("[;'\"\\\\]", "");
    }

    /**
     * Validate channel name (based on ChannelVersion table)
     *
     * @param channel Channel code (AD, OS, WB, RT, etc.)
     * @return true if valid channel
     */
    public static boolean isValidChannel(String channel) {
        if (channel == null) {
            return false;
        }

        String upperChannel = channel.trim().toUpperCase();

        // Check valid channels from database
        if (VALID_CHANNELS.contains(upperChannel)) {
            return true;
        }

        // Check legacy channel names for backward compatibility
        return LEGACY_CHANNELS.contains(upperChannel);
    }

    /**
     * Normalize channel name to database format
     * Converts legacy names to standard codes
     *
     * @param channel Channel name (can be legacy format)
     * @return Normalized channel code
     */
    public static String normalizeChannel(String channel) {
        if (channel == null) {
            return null;
        }

        String upperChannel = channel.trim().toUpperCase();

        // Convert legacy names to standard codes
        return switch (upperChannel) {
            case "IDXMOBILE", "MOBILE" -> "AD"; // Default to Android for mobile
            case "WEB" -> "WB";
            default -> upperChannel;
        };
    }

    /**
     * Validate AppCode format
     * Format: 2-6 uppercase letters + 2 digits (e.g., BZADR01, IDXM01)
     *
     * @param appCode Application code
     * @return true if valid format
     */
    public static boolean isValidAppCode(String appCode) {
        if (appCode == null) {
            return false;
        }
        // Pattern: 2-6 uppercase letters followed by 2 digits
        return appCode.matches("^[A-Z]{2,6}\\d{2}$");
    }

    /**
     * Extract product prefix from AppCode
     * Example: BZADR01 -> BZ, IDXM01 -> IDXM
     *
     * @param appCode Application code
     * @return Product prefix or null
     */
    public static String extractProductPrefix(String appCode) {
        if (appCode == null || !isValidAppCode(appCode)) {
            return null;
        }
        // Remove last 2 digits
        return appCode.substring(0, appCode.length() - 2);
    }
}