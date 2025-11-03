package com.strade.auth_app.scheduler;

import com.strade.auth_app.config.properties.SchedulerProperties;
import com.strade.auth_app.repository.jpa.AccessTokenDenyJtiRepository;
import com.strade.auth_app.repository.jpa.OtpChallengeRepository;
import com.strade.auth_app.repository.jpa.RefreshTokenRepository;
import com.strade.auth_app.repository.procedure.CleanupProcedureRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;

/**
 * Scheduled tasks for token cleanup
 */
@Component
@Slf4j
@RequiredArgsConstructor
@ConditionalOnProperty(
        prefix = "app.scheduler.token-cleanup",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
)
public class TokenCleanupScheduler {

    private final AccessTokenDenyJtiRepository denyJtiRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final OtpChallengeRepository otpChallengeRepository;
    private final CleanupProcedureRepository cleanupProcedureRepository;
    private final SchedulerProperties schedulerProperties;

    /**
     * Cleanup expired access token denylists
     */
    @Scheduled(cron = "0 0 * * * *")
    public void cleanupExpiredDenylist() {
        if (!schedulerProperties.getTokenCleanup().isExpiredDenylist()) {
            log.debug("cleanupExpiredDenylist is disabled");
            return;
        }

        log.info("Starting cleanup of expired access token denylists");

        try {
            LocalDateTime threshold = LocalDateTime.now();
            denyJtiRepository.deleteByExpiresAtBefore(threshold);
            log.info("Completed cleanup of expired access token denylists");
        } catch (Exception e) {
            log.error("Error during denylist cleanup", e);
        }
    }

    /**
     * Cleanup old revoked refresh tokens
     */
    @Scheduled(cron = "0 0 2 * * *")
    public void cleanupRevokedRefreshTokens() {
        if (!schedulerProperties.getTokenCleanup().isRevokedRefreshTokens()) {
            log.debug("cleanupRevokedRefreshTokens is disabled");
            return;
        }

        log.info("Starting cleanup of old revoked refresh tokens");

        try {
            LocalDateTime threshold = LocalDateTime.now().minus(7, ChronoUnit.DAYS);
            refreshTokenRepository.deleteByRevokedAtIsNotNullAndRevokedAtBefore(threshold);
            log.info("Completed cleanup of old revoked refresh tokens");
        } catch (Exception e) {
            log.error("Error during refresh token cleanup", e);
        }
    }

    /**
     * Mark expired OTP challenges
     */
    @Scheduled(fixedRate = 300000)
    public void markExpiredOtpChallenges() {
        if (!schedulerProperties.getTokenCleanup().isExpiredOtpChallenges()) {
            return;
        }

        log.debug("Marking expired OTP challenges");

        try {
            otpChallengeRepository.markExpiredChallenges(LocalDateTime.now());
        } catch (Exception e) {
            log.error("Error marking expired OTP challenges", e);
        }
    }

    /**
     * Cleanup old OTP challenges
     */
    @Scheduled(cron = "0 0 3 * * *")
    public void cleanupOldOtpChallenges() {
        if (!schedulerProperties.getTokenCleanup().isOldOtpChallenges()) {
            log.debug("cleanupOldOtpChallenges is disabled");
            return;
        }

        log.info("Starting cleanup of old OTP challenges");

        try {
            LocalDateTime threshold = LocalDateTime.now().minus(30, ChronoUnit.DAYS);
            otpChallengeRepository.deleteByCreatedAtBefore(threshold);
            log.info("Completed cleanup of old OTP challenges");
        } catch (Exception e) {
            log.error("Error during OTP challenge cleanup", e);
        }
    }

    /**
     * Comprehensive cleanup via stored procedure
     */
    @Scheduled(cron = "0 0 1 * * *")
    public void comprehensiveCleanup() {
        if (!schedulerProperties.getTokenCleanup().isComprehensiveCleanup()) {
            log.debug("comprehensiveCleanup is disabled");
            return;
        }

        log.info("Starting comprehensive cleanup via stored procedure");

        try {
            cleanupProcedureRepository.cleanupExpiredTokens();
            log.info("Completed comprehensive cleanup");
        } catch (Exception e) {
            log.error("Error during comprehensive cleanup", e);
        }
    }
}