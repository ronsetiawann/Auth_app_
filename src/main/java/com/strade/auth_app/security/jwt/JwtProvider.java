package com.strade.auth_app.security.jwt;

import com.strade.auth_app.config.properties.AppProperties;
import com.strade.auth_app.entity.KeyStore;
import com.strade.auth_app.exception.ErrorCode;
import com.strade.auth_app.exception.TokenException;
import com.strade.auth_app.repository.jpa.KeyStoreRepository;
import com.strade.auth_app.util.DateTimeUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.*;

/**
 * JWT token generator
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JwtProvider {

    private final KeyManager keyManager;
    private final AppProperties appProperties;
    private final KeyStoreRepository keyStoreRepository;

    /**
     * Generate access token
     *
     * @param userId User ID
     * @param sessionId Session ID
     * @param additionalClaims Additional claims
     * @return JWT access token
     */
    public String generateAccessToken(
            String userId,
            UUID sessionId,
            Map<String, Object> additionalClaims
    ) {
        log.debug("Generating access token for userId: {}, sessionId: {}", userId, sessionId);

        // Get active key ID
        String kid = keyStoreRepository.findActiveKey()
                .map(KeyStore::getKid)
                .orElseThrow(() -> new TokenException(
                        ErrorCode.INTERNAL_SERVER_ERROR,
                        "No active JWT key found"
                ));

        LocalDateTime now = LocalDateTime.now();
        LocalDateTime expiration = now.plus(
                appProperties.getJwt().getAccessToken().getExpirationMinutes(),
                ChronoUnit.MINUTES
        );

        Map<String, Object> claims = new HashMap<>();
        claims.put("sessionId", sessionId.toString());
        claims.put("type", "access");

        if (additionalClaims != null) {
            claims.putAll(additionalClaims);
        }

        String token = Jwts.builder()
                .setHeaderParam("kid", kid)
                .setId(UUID.randomUUID().toString())
                .setSubject(userId)
                .setIssuer(appProperties.getJwt().getIssuer())
                .setIssuedAt(DateTimeUtil.toDate(now))
                .setExpiration(DateTimeUtil.toDate(expiration))
                .addClaims(claims)
                .signWith(keyManager.getPrivateKey(), SignatureAlgorithm.RS256)
                .compact();

        log.debug("Access token generated successfully for userId: {}", userId);
        return token;
    }

    /**
     * Generate refresh token
     * Simple opaque token (not JWT)
     *
     * @param sessionId Session ID
     * @return Refresh token
     */
    public String generateRefreshToken(UUID sessionId) {
        log.debug("Generating refresh token for sessionId: {}", sessionId);

        // Format: {UUID}-{timestamp}
        String token = UUID.randomUUID().toString() + "-" + System.currentTimeMillis();

        // Base64 encode for uniformity
        return Base64.getUrlEncoder().withoutPadding().encodeToString(
                token.getBytes()
        );
    }

    /**
     * Hash refresh token for storage
     *
     * @param refreshToken Refresh token
     * @return Hashed token
     */
    public byte[] hashRefreshToken(String refreshToken) {
        return com.strade.auth_app.util.HashUtil.sha256(refreshToken);
    }

    /**
     * Get refresh token expiration
     *
     * @return Expiration LocalDateTime
     */
    public LocalDateTime getRefreshTokenExpiration() {
        return LocalDateTime.now().plus(
                appProperties.getJwt().getRefreshToken().getExpirationDays(),
                ChronoUnit.DAYS
        );
    }
}
