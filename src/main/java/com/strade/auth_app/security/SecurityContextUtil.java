package com.strade.auth_app.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Optional;
import java.util.UUID;

/**
 * Utility for accessing current authentication context
 */
public final class SecurityContextUtil {

    private SecurityContextUtil() {
        throw new IllegalStateException("Utility class");
    }

    /**
     * Get current authentication context
     *
     * @return Authentication context or empty
     */
    public static Optional<AuthenticationContext> getCurrentContext() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            return Optional.empty();
        }

        Object principal = authentication.getPrincipal();
        if (principal instanceof AuthenticationContext) {
            return Optional.of((AuthenticationContext) principal);
        }

        return Optional.empty();
    }

    /**
     * Get current user ID
     *
     * @return User ID or empty
     */
    public static Optional<String> getCurrentUserId() {
        return getCurrentContext().map(AuthenticationContext::getUserId);
    }

    /**
     * Get current session ID
     *
     * @return Session ID or empty
     */
    public static Optional<UUID> getCurrentSessionId() {
        return getCurrentContext().map(AuthenticationContext::getSessionId);
    }

    /**
     * Check if user is authenticated
     *
     * @return true if authenticated
     */
    public static boolean isAuthenticated() {
        return getCurrentContext().isPresent();
    }

    /**
     * Require authentication (throw exception if not authenticated)
     *
     * @return Authentication context
     * @throws IllegalStateException if not authenticated
     */
    public static AuthenticationContext requireAuthentication() {
        return getCurrentContext()
                .orElseThrow(() -> new IllegalStateException("Not authenticated"));
    }

    /**
     * Clear security context
     */
    public static void clearContext() {
        SecurityContextHolder.clearContext();
    }
}
