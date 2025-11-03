package com.strade.auth_app.util;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * Utility class for secure random generation
 */
public final class RandomUtil {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private static final String ALPHANUMERIC = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    private static final String NUMERIC = "0123456789";
    private static final String ALPHA_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String ALPHA_LOWER = "abcdefghijklmnopqrstuvwxyz";

    private RandomUtil() {
        throw new IllegalStateException("Utility class");
    }

    /**
     * Generate random numeric OTP
     *
     * @param length Length of OTP (typically 6)
     * @return Numeric OTP string
     */
    public static String generateNumericOtp(int length) {
        StringBuilder otp = new StringBuilder();
        for (int i = 0; i < length; i++) {
            otp.append(SECURE_RANDOM.nextInt(10));
        }
        return otp.toString();
    }

    /**
     * Generate random alphanumeric string
     *
     * @param length Length of string
     * @return Random alphanumeric string
     */
    public static String generateAlphanumeric(int length) {
        StringBuilder result = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            result.append(ALPHANUMERIC.charAt(SECURE_RANDOM.nextInt(ALPHANUMERIC.length())));
        }
        return result.toString();
    }

    /**
     * Generate backup codes
     * Format: XXXX-XXXX-XXXX
     *
     * @param count Number of codes to generate
     * @return List of backup codes
     */
    public static List<String> generateBackupCodes(int count) {
        List<String> codes = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            String code = generateAlphanumeric(12);
            // Format as XXXX-XXXX-XXXX
            String formatted = code.substring(0, 4) + "-" +
                    code.substring(4, 8) + "-" +
                    code.substring(8, 12);
            codes.add(formatted);
        }
        return codes;
    }

    /**
     * Generate TOTP secret (Base32)
     *
     * @return Base32-encoded secret (32 characters)
     */
    public static String generateTotpSecret() {
        // Base32 alphabet (RFC 4648)
        String base32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        StringBuilder secret = new StringBuilder(32);
        for (int i = 0; i < 32; i++) {
            secret.append(base32.charAt(SECURE_RANDOM.nextInt(base32.length())));
        }
        return secret.toString();
    }

    /**
     * Generate secure random bytes
     *
     * @param length Number of bytes
     * @return Random bytes
     */
    public static byte[] generateRandomBytes(int length) {
        byte[] bytes = new byte[length];
        SECURE_RANDOM.nextBytes(bytes);
        return bytes;
    }

    /**
     * Generate UUID-like string
     *
     * @return UUID string
     */
    public static String generateUuid() {
        return java.util.UUID.randomUUID().toString();
    }
}
