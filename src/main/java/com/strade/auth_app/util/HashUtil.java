package com.strade.auth_app.util;

import com.strade.auth_app.constant.AppConstants;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Hex;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Utility class for hashing operations
 */
@Slf4j
public final class HashUtil {

    private HashUtil() {
        throw new IllegalStateException("Utility class");
    }

    /**
     * Hash data using SHA-256
     *
     * @param data Data to hash
     * @return Hashed bytes
     */
    public static byte[] sha256(String data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(data.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            log.error("SHA-256 algorithm not available", e);
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    /**
     * Hash data using SHA-256 with application salt
     * Used for OTP codes, refresh tokens, backup codes
     *
     * @param data Data to hash
     * @return Hashed bytes
     */
    public static byte[] sha256WithSalt(String data) {
        return sha256(data + AppConstants.SALT);
    }

    /**
     * Hash data using SHA-512
     *
     * @param data Data to hash
     * @return Hashed bytes
     */
    public static byte[] sha512(String data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-512");
            return digest.digest(data.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            log.error("SHA-512 algorithm not available", e);
            throw new IllegalStateException("SHA-512 not available", e);
        }
    }

    /**
     * Convert byte array to hex string
     *
     * @param bytes Byte array
     * @return Hex string
     */
    public static String toHex(byte[] bytes) {
        return Hex.encodeHexString(bytes);
    }

    /**
     * Convert hex string to byte array
     *
     * @param hex Hex string
     * @return Byte array
     */
    public static byte[] fromHex(String hex) {
        try {
            return Hex.decodeHex(hex);
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid hex string", e);
        }
    }

    /**
     * Compare two byte arrays in constant time
     * Prevents timing attacks
     *
     * @param a First array
     * @param b Second array
     * @return true if equal, false otherwise
     */
    public static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a == null || b == null) {
            return a == b;
        }

        if (a.length != b.length) {
            return false;
        }

        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }

        return result == 0;
    }

    /**
     * Verify hashed value
     *
     * @param plainText Plain text
     * @param hash Expected hash
     * @return true if match, false otherwise
     */
    public static boolean verify(String plainText, byte[] hash) {
        byte[] computed = sha256WithSalt(plainText);
        return constantTimeEquals(computed, hash);
    }
}
