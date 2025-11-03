package com.strade.auth_app.repository.procedure;

import java.util.UUID;

/**
 * Repository for session-related stored procedures
 */
public interface SessionProcedureRepository {

    /**
     * Store refresh token on login
     *
     * @param sessionId Session ID
     * @param refreshTokenHash Hashed refresh token
     * @param refreshTokenExp Expiration time
     * @return Refresh token ID
     */
    UUID storeRefreshOnLogin(
            UUID sessionId,
            byte[] refreshTokenHash,
            java.time.LocalDateTime refreshTokenExp
    );

    /**
     * Rotate refresh token with reuse detection
     *
     * @param sessionId Session ID
     * @param oldRefreshHash Old token hash
     * @param newRefreshHash New token hash
     * @param newRefreshExp New expiration
     * @throws RuntimeException if token reuse detected
     */
    void rotateRefreshToken(
            UUID sessionId,
            byte[] oldRefreshHash,
            byte[] newRefreshHash,
            java.time.LocalDateTime newRefreshExp
    );

    /**
     * Revoke a single session
     */
    void revokeSession(UUID sessionId, String reason);

    /**
     * Revoke all sessions for a user
     */
    void revokeAllSessionsForUser(
            String userId,
            UUID exceptSessionId,
            String reason
    );

    /**
     * Verify access token claims
     *
     * @return true if valid, false otherwise
     */
    boolean verifyAccessClaims(
            UUID sessionId,
            String jti,
            String userId
    );
}
