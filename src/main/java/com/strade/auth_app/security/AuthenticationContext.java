package com.strade.auth_app.security;

import com.strade.auth_app.security.jwt.JwtClaims;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.List;
import java.util.UUID;

/**
 * Authentication context for current request
 * Stored in Spring Security Context
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthenticationContext {

    private String userId;
    private UUID sessionId;
    private String jti;
    private List<String> permissions;
    private boolean authenticated;

    // Additional metadata
    private String channel;
    private String deviceId;
    private String ipAddress;

    /**
     * Create from JWT claims
     */
    public static AuthenticationContext fromJwtClaims(JwtClaims claims) {
        return AuthenticationContext.builder()
                .userId(claims.getUserId())
                .sessionId(claims.getSessionId())
                .jti(claims.getJti())
                .permissions(claims.getPermissions())
                .authenticated(true)
                .build();
    }

    /**
     * Get authorities for Spring Security
     */
    public Collection<? extends GrantedAuthority> getAuthorities() {
        if (permissions == null || permissions.isEmpty()) {
            return List.of();
        }
        return permissions.stream()
                .map(perm -> (GrantedAuthority) () -> perm)
                .toList();
    }

    /**
     * Check if user has specific permission
     */
    public boolean hasPermission(String permission) {
        return permissions != null && permissions.contains(permission);
    }

    /**
     * Check if user has any of the permissions
     */
    public boolean hasAnyPermission(String... permissions) {
        if (this.permissions == null || this.permissions.isEmpty()) {
            return false;
        }
        for (String permission : permissions) {
            if (this.permissions.contains(permission)) {
                return true;
            }
        }
        return false;
    }
}
