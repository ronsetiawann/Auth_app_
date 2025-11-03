package com.strade.auth_app.scheduler;

import com.strade.auth_app.config.properties.SchedulerProperties;
import com.strade.auth_app.constant.AppConstants;
import com.strade.auth_app.entity.Session;
import com.strade.auth_app.repository.jpa.SessionRepository;
import com.strade.auth_app.service.DeviceService;
import com.strade.auth_app.service.cache.SessionCacheService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.List;

/**
 * Scheduled tasks for session management
 */
@Component
@Slf4j
@RequiredArgsConstructor
@ConditionalOnProperty(
        prefix = "app.scheduler.session-cleanup",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
)
public class SessionCleanupScheduler {

    private final SessionRepository sessionRepository;
    private final SessionCacheService sessionCacheService;
    private final DeviceService deviceService;
    private final SchedulerProperties schedulerProperties;

    @Value("${app.session.inactive-threshold-minutes:30}")
    private Integer inactiveThresholdMinutes;

    /**
     * Mark inactive sessions as expired (only for non-trusted devices)
     */
    @Scheduled(fixedRate = 600000)
    @Transactional
    public void markInactiveSessions() {
        if (!schedulerProperties.getSessionCleanup().isMarkInactive()) {
            return;
        }

        log.debug("Checking for inactive sessions (non-trusted devices only)");

        try {
            LocalDateTime threshold = LocalDateTime.now().minus(inactiveThresholdMinutes, ChronoUnit.MINUTES);
            LocalDateTime now = LocalDateTime.now();

            List<Session> inactiveSessions = sessionRepository.findInactiveSessions(threshold, now);

            if (!inactiveSessions.isEmpty()) {
                log.info("Found {} potentially inactive sessions to check", inactiveSessions.size());

                for (Session session : inactiveSessions) {
                    // Check if this is a trusted device
                    boolean isTrusted = deviceService.isTrustedDevice(
                            session.getUserId(),
                            session.getDeviceId(),
                            session.getChannel()
                    );

                    if (isTrusted) {
                        // SKIP: Don't expire sessions from trusted devices
                        log.debug("Skipping inactive check for trusted device session: {}",
                                session.getSessionId());
                        continue;
                    }

                    // Only expire non-trusted device sessions due to inactivity
                    session.setStatus(AppConstants.SESSION_STATUS_EXPIRED);
                    session.setRevokedReason("Inactive timeout (non-trusted device)");
                    sessionRepository.save(session);
                    sessionCacheService.invalidateSession(session.getSessionId());
                }

                log.info("Marked inactive sessions as expired");
            }
        } catch (Exception e) {
            log.error("Error marking inactive sessions", e);
        }
    }

    /**
     * Cleanup expired sessions from database
     */
    @Scheduled(cron = "0 0 4 * * *")
    @Transactional
    public void cleanupExpiredSessions() {
        if (!schedulerProperties.getSessionCleanup().isCleanupExpired()) {
            log.debug("cleanupExpiredSessions is disabled");
            return;
        }

        log.info("Starting cleanup of expired sessions");

        try {
            // Implementation here
            log.info("Completed cleanup of expired sessions");
        } catch (Exception e) {
            log.error("Error during session cleanup", e);
        }
    }
}