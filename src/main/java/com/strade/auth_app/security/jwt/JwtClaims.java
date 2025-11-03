package com.strade.auth_app.security.jwt;

import com.strade.auth_app.util.DateTimeUtil;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * JWT Claims data transfer object
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class JwtClaims {

    // Standard claims
    private String jti;           // JWT ID
    private String sub;           // Subject (userId)
    private String iss;           // Issuer
    private LocalDateTime iat;          // Issued at
    private LocalDateTime exp;          // Expiration

    // Custom claims
    private UUID sessionId;
    private String type;          // "access" or "refresh"
    private List<String> permissions;
    private Map<String, Object> metadata;

    /**
     * Create JwtClaims from io.jsonwebtoken.Claims
     */
    public static JwtClaims from(io.jsonwebtoken.Claims claims) {
        return JwtClaims.builder()
                .jti(claims.getId())
                .sub(claims.getSubject())
                .iss(claims.getIssuer())
                .iat(DateTimeUtil.fromDate(claims.getIssuedAt()))
                .exp(DateTimeUtil.fromDate(claims.getExpiration()))
                .sessionId(UUID.fromString((String) claims.get("sessionId")))
                .type((String) claims.get("type"))
                .permissions((List<String>) claims.get("permissions"))
                .metadata((Map<String, Object>) claims.get("metadata"))
                .build();
    }

    /**
     * Get userId from subject
     */
    public String getUserId() {
        return sub;
    }

    /**
     * Check if token is expired
     */
    public boolean isExpired() {
        return exp.isBefore(LocalDateTime.now());
    }

    /**
     * Check if token is access token
     */
    public boolean isAccessToken() {
        return "access".equals(type);
    }

    /**
     * Get authorities for Spring Security
     */
    public List<org.springframework.security.core.GrantedAuthority> getAuthorities() {
        if (permissions == null || permissions.isEmpty()) {
            return List.of();
        }
        return permissions.stream()
                .map(perm -> (org.springframework.security.core.GrantedAuthority)
                        () -> perm)
                .toList();
    }
}
