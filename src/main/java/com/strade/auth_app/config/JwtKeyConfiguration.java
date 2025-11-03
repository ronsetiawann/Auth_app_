package com.strade.auth_app.config;

import com.strade.auth_app.security.jwt.KeyManager;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.PrivateKey;
import java.security.PublicKey;

@Slf4j
@Configuration
public class JwtKeyConfiguration {

    @Value("${app.jwt.private-key-path}")
    private String privateKeyPath;

    @Value("${app.jwt.public-key-path}")
    private String publicKeyPath;

    @Bean
    public PrivateKey privateKey() throws Exception {
        log.info("🔑 Loading private key from: {}", privateKeyPath);

        if (privateKeyPath.startsWith("classpath:")) {
            return KeyManager.loadPrivateKeyFromResource(privateKeyPath);
        } else {
            return KeyManager.loadPrivateKey(privateKeyPath);
        }
    }

    @Bean
    public PublicKey publicKey() throws Exception {
        log.info("🔑 Loading public key from: {}", publicKeyPath);

        if (publicKeyPath.startsWith("classpath:")) {
            return KeyManager.loadPublicKeyFromResource(publicKeyPath);
        } else {
            return KeyManager.loadPublicKey(publicKeyPath);
        }
    }

    @Bean
    public KeyManager keyManager(PrivateKey privateKey, PublicKey publicKey) {
        log.info("✅ KeyManager bean created with RSA key pair");
        return new KeyManager(privateKey, publicKey);
    }
}
