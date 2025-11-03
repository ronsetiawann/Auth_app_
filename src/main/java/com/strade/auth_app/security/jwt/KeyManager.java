package com.strade.auth_app.security.jwt;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Manages RSA private/public key pair for JWT signing
 */
@Slf4j
@Getter
@Component
public class KeyManager {

    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    public KeyManager(PrivateKey privateKey, PublicKey publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        log.info("KeyManager initialized with RSA key pair");
    }

    /**
     * Load private key from PEM file
     *
     * @param path Path to private key file
     * @return PrivateKey
     */
    public static PrivateKey loadPrivateKey(String path) throws Exception {
        log.info("Loading private key from: {}", path);

        String key = new String(Files.readAllBytes(Paths.get(path)))
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        byte[] keyBytes = Base64.getDecoder().decode(key);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        return keyFactory.generatePrivate(spec);
    }

    /**
     * Load public key from PEM file
     *
     * @param path Path to public key file
     * @return PublicKey
     */
    public static PublicKey loadPublicKey(String path) throws Exception {
        log.info("Loading public key from: {}", path);

        String key = new String(Files.readAllBytes(Paths.get(path)))
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        byte[] keyBytes = Base64.getDecoder().decode(key);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        return keyFactory.generatePublic(spec);
    }

    /**
     * Load private key from classpath resource
     */
    public static PrivateKey loadPrivateKeyFromResource(String resourcePath) throws Exception {
        log.info("Loading private key from resource: {}", resourcePath);

        String path = resourcePath.replace("classpath:", "");
        String key = new String(
                KeyManager.class.getClassLoader().getResourceAsStream(path).readAllBytes()
        )
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        byte[] keyBytes = Base64.getDecoder().decode(key);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        return keyFactory.generatePrivate(spec);
    }

    /**
     * Load public key from classpath resource
     */
    public static PublicKey loadPublicKeyFromResource(String resourcePath) throws Exception {
        log.info("Loading public key from resource: {}", resourcePath);

        String path = resourcePath.replace("classpath:", "");
        String key = new String(
                KeyManager.class.getClassLoader().getResourceAsStream(path).readAllBytes()
        )
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        byte[] keyBytes = Base64.getDecoder().decode(key);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        return keyFactory.generatePublic(spec);
    }
}
