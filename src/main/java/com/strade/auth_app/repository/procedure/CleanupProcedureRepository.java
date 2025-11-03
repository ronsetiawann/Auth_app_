package com.strade.auth_app.repository.procedure;

/**
 * Repository for maintenance stored procedures
 */
public interface CleanupProcedureRepository {

    /**
     * Cleanup expired tokens and old data
     */
    void cleanupExpiredTokens();

    /**
     * Security monitoring job
     */
    void securityMonitor();
}
