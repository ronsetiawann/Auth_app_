package com.strade.auth_app.security.jwt;

import com.strade.auth_app.config.properties.AppProperties;
import com.strade.auth_app.entity.KeyStore;
import com.strade.auth_app.exception.ErrorCode;
import com.strade.auth_app.exception.TokenException;
import com.strade.auth_app.repository.jpa.AccessTokenDenyJtiRepository;
import com.strade.auth_app.repository.jpa.KeyStoreRepository;
import com.strade.auth_app.repository.jpa.SessionRepository;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.SignatureException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.security.PublicKey;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.UUID;

/**
 * JWT token validator (for jjwt 0.12.5)
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JwtValidator {

    private final KeyManager keyManager;
    private final AppProperties appProperties;
    private final KeyStoreRepository keyStoreRepository;
    private final AccessTokenDenyJtiRepository denyJtiRepository;
    private final SessionRepository sessionRepository;

    /**
     * Validate and parse JWT token
     */
    public JwtClaims validateAndParseClaims(String token) {
        try {
            // 1. Extract kid from header
            String kid = extractKid(token);
            log.debug("Validating token with kid: {}", kid);

            // 2. Get public key for this kid
            PublicKey publicKey = getPublicKey(kid);

            // 3. Parse and validate token (jjwt 0.12.5 API)
            JwtParser parser = Jwts.parser()
                    .verifyWith(publicKey)
                    .requireIssuer(appProperties.getJwt().getIssuer())
                    .build();

            Claims claims = parser.parseSignedClaims(token).getPayload();

            // 4. Check if JTI is in denylist
            String jti = claims.getId();
            if (denyJtiRepository.existsByJtiAndExpiresAtAfter(jti, LocalDateTime.now())) {
                log.warn("Token JTI is denylisted: {}", jti);
                throw new TokenException(ErrorCode.TOKEN_REVOKED, "Token has been revoked");
            }

            // 5. Check if session is still active
            UUID sessionId = UUID.fromString((String) claims.get("sessionId"));
            boolean sessionActive = sessionRepository.existsBySessionIdAndStatus(sessionId, (byte) 1);

            if (!sessionActive) {
                log.warn("Session is not active: {}", sessionId);
                throw new TokenException(ErrorCode.SESSION_INACTIVE, "Session is no longer active");
            }

            // 6. Convert to JwtClaims DTO
            JwtClaims jwtClaims = JwtClaims.from(claims);
            log.debug("Token validated successfully for userId: {}", jwtClaims.getUserId());

            return jwtClaims;

        } catch (ExpiredJwtException e) {
            log.warn("Token expired: {}", e.getMessage());
            throw new TokenException(ErrorCode.TOKEN_EXPIRED, "Token has expired", e);
        } catch (UnsupportedJwtException e) {
            log.warn("Unsupported token: {}", e.getMessage());
            throw new TokenException(ErrorCode.TOKEN_INVALID, "Unsupported token", e);
        } catch (MalformedJwtException e) {
            log.warn("Malformed token: {}", e.getMessage());
            throw new TokenException(ErrorCode.TOKEN_MALFORMED, "Malformed token", e);
        } catch (SignatureException e) {
            log.warn("Invalid signature: {}", e.getMessage());
            throw new TokenException(ErrorCode.TOKEN_SIGNATURE_INVALID, "Invalid token signature", e);
        } catch (JwtException e) {
            log.warn("JWT error: {}", e.getMessage());
            throw new TokenException(ErrorCode.TOKEN_INVALID, "Invalid token", e);
        }
    }

    /**
     * Extract kid from JWT header without validation
     */
    private String extractKid(String token) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length < 2) {
                throw new TokenException(ErrorCode.TOKEN_MALFORMED, "Invalid token format");
            }

            String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]));

            // Simple JSON parsing for kid
            String kidPrefix = "\"kid\":\"";
            int kidStart = headerJson.indexOf(kidPrefix);
            if (kidStart == -1) {
                // No kid in header, use default key
                return keyStoreRepository.findActiveKey()
                        .map(KeyStore::getKid)
                        .orElseThrow(() -> new TokenException(
                                ErrorCode.TOKEN_INVALID,
                                "No kid in token and no active key found"
                        ));
            }

            kidStart += kidPrefix.length();
            int kidEnd = headerJson.indexOf("\"", kidStart);

            return headerJson.substring(kidStart, kidEnd);

        } catch (Exception e) {
            log.error("Failed to extract kid from token", e);
            throw new TokenException(ErrorCode.TOKEN_MALFORMED, "Failed to extract kid", e);
        }
    }

    /**
     * Get public key for kid
     */
    private PublicKey getPublicKey(String kid) {
        return keyStoreRepository.findByKid(kid)
                .map(keyStore -> {
                    try {
                        return KeyManager.loadPublicKeyFromResource(
                                "data:," + keyStore.getPublicKeyPem()
                        );
                    } catch (Exception e) {
                        // Fallback to default key
                        return keyManager.getPublicKey();
                    }
                })
                .orElse(keyManager.getPublicKey());
    }
}