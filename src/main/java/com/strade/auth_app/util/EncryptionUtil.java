package com.strade.auth_app.util;

import lombok.extern.slf4j.Slf4j;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Utility class for AES-256-GCM encryption/decryption
 * Used for encrypting TOTP secrets
 */
@Slf4j
public final class EncryptionUtil {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int KEY_SIZE = 256;
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;

    private EncryptionUtil() {
        throw new IllegalStateException("Utility class");
    }

    /**
     * Generate a new AES-256 key
     *
     * @return Base64-encoded key
     */
    public static String generateKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
            keyGen.init(KEY_SIZE, new SecureRandom());
            SecretKey secretKey = keyGen.generateKey();
            return Base64.getEncoder().encodeToString(secretKey.getEncoded());
        } catch (Exception e) {
            log.error("Failed to generate encryption key", e);
            throw new IllegalStateException("Key generation failed", e);
        }
    }

    /**
     * Encrypt data using AES-256-GCM
     *
     * @param plainText Plain text to encrypt
     * @param base64Key Base64-encoded encryption key
     * @return Encrypted bytes (IV + ciphertext)
     */
    public static byte[] encrypt(String plainText, String base64Key) {
        try {
            // Decode key
            byte[] keyBytes = Base64.getDecoder().decode(base64Key);
            SecretKey secretKey = new SecretKeySpec(keyBytes, ALGORITHM);

            // Generate IV
            byte[] iv = new byte[GCM_IV_LENGTH];
            new SecureRandom().nextBytes(iv);

            // Initialize cipher
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);

            // Encrypt
            byte[] cipherText = cipher.doFinal(plainText.getBytes(java.nio.charset.StandardCharsets.UTF_8));

            // Combine IV + ciphertext
            byte[] encrypted = new byte[GCM_IV_LENGTH + cipherText.length];
            System.arraycopy(iv, 0, encrypted, 0, GCM_IV_LENGTH);
            System.arraycopy(cipherText, 0, encrypted, GCM_IV_LENGTH, cipherText.length);

            return encrypted;

        } catch (Exception e) {
            log.error("Encryption failed", e);
            throw new IllegalStateException("Encryption failed", e);
        }
    }

    /**
     * Decrypt data using AES-256-GCM
     *
     * @param encrypted Encrypted bytes (IV + ciphertext)
     * @param base64Key Base64-encoded encryption key
     * @return Decrypted plain text
     */
    public static String decrypt(byte[] encrypted, String base64Key) {
        try {
            // Decode key
            byte[] keyBytes = Base64.getDecoder().decode(base64Key);
            SecretKey secretKey = new SecretKeySpec(keyBytes, ALGORITHM);

            // Extract IV
            byte[] iv = new byte[GCM_IV_LENGTH];
            System.arraycopy(encrypted, 0, iv, 0, GCM_IV_LENGTH);

            // Extract ciphertext
            byte[] cipherText = new byte[encrypted.length - GCM_IV_LENGTH];
            System.arraycopy(encrypted, GCM_IV_LENGTH, cipherText, 0, cipherText.length);

            // Initialize cipher
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);

            // Decrypt
            byte[] plainText = cipher.doFinal(cipherText);
            return new String(plainText, java.nio.charset.StandardCharsets.UTF_8);

        } catch (Exception e) {
            log.error("Decryption failed", e);
            throw new IllegalStateException("Decryption failed", e);
        }
    }
}
