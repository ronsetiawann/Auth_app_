package com.strade.auth_app.util;

/**
 * Generate encryption key for first time setup
 * Run this once to generate ENCRYPTION_KEY for application.yml
 */
public class KeyGenerator {

    public static void main(String[] args) {
        System.out.println("=== Encryption Key Generator ===");
        System.out.println();

        // Generate AES-256 encryption key
        String encryptionKey = EncryptionUtil.generateKey();
        System.out.println("Generated Encryption Key (AES-256):");
        System.out.println(encryptionKey);
        System.out.println();

        System.out.println("Add this to your application.yml or environment variables:");
        System.out.println("app.security.encryption-key=" + encryptionKey);
        System.out.println();
        System.out.println("Or as environment variable:");
        System.out.println("export ENCRYPTION_KEY=" + encryptionKey);
        System.out.println();

        System.out.println("IMPORTANT: Keep this key secure! Store it safely.");
        System.out.println("If this key is lost, all encrypted TOTP secrets cannot be decrypted.");
    }
}
