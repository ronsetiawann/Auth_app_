package com.strade.auth_app.scheduler;

import com.strade.auth_app.config.properties.SchedulerProperties;
import com.strade.auth_app.constant.EventTypes;
import com.strade.auth_app.repository.jpa.AuthEventLogRepository;
import com.strade.auth_app.repository.procedure.CleanupProcedureRepository;
import com.strade.auth_app.service.EventLogService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;

/**
 * Security monitoring scheduler
 */
@Component
@Slf4j
@RequiredArgsConstructor
@ConditionalOnProperty(
        prefix = "app.scheduler.security-monitor",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
)
public class SecurityMonitorScheduler {

    private final AuthEventLogRepository eventLogRepository;
    private final CleanupProcedureRepository cleanupProcedureRepository;
    private final EventLogService eventLogService;
    private final SchedulerProperties schedulerProperties;

    @Scheduled(fixedRate = 900000)
    public void runSecurityMonitor() {
        if (!schedulerProperties.getSecurityMonitor().isMonitor()) {
            return;
        }

        log.debug("Running security monitor");

        try {
            cleanupProcedureRepository.securityMonitor();
            eventLogService.logEvent(
                    null, null,
                    EventTypes.SECURITY_MONITOR_TICK,
                    "Security monitor executed"
            );
        } catch (Exception e) {
            log.error("Error during security monitoring", e);
        }
    }

    @Scheduled(cron = "0 0 * * * *")
    public void monitorLoginFailures() {
        if (!schedulerProperties.getSecurityMonitor().isLoginFailures()) {
            return;
        }

        log.debug("Monitoring login failures");

        try {
            LocalDateTime since = LocalDateTime.now().minus(1, ChronoUnit.HOURS);
            var failedLogins = eventLogRepository.findByEventTypeAndEventTimeAfter(
                    EventTypes.LOGIN_FAILED, since
            );

            Map<String, Long> failuresByUser = new HashMap<>();
            for (var event : failedLogins) {
                if (event.getUserId() != null) {
                    failuresByUser.merge(event.getUserId(), 1L, Long::sum);
                }
            }

            for (Map.Entry<String, Long> entry : failuresByUser.entrySet()) {
                if (entry.getValue() > 10) {
                    log.warn("SECURITY ALERT: User {} has {} failed login attempts",
                            entry.getKey(), entry.getValue());

                    eventLogService.logEvent(
                            entry.getKey(), null,
                            EventTypes.SECURITY_ALERT_MULTIPLE_FAILURES,
                            "Multiple login failures: " + entry.getValue(),
                            Map.of("failureCount", entry.getValue())
                    );
                }
            }
        } catch (Exception e) {
            log.error("Error monitoring login failures", e);
        }
    }

    @Scheduled(fixedRate = 1800000)
    public void monitorTokenReuse() {
        if (!schedulerProperties.getSecurityMonitor().isTokenReuse()) {
            return;
        }

        log.debug("Monitoring token reuse attempts");

        try {
            LocalDateTime since = LocalDateTime.now().minus(30, ChronoUnit.MINUTES);
            var reuseEvents = eventLogRepository.findByEventTypeAndEventTimeAfter(
                    EventTypes.REFRESH_REUSE_DETECTED, since
            );

            if (!reuseEvents.isEmpty()) {
                log.warn("SECURITY ALERT: {} token reuse attempts detected",
                        reuseEvents.size());
            }
        } catch (Exception e) {
            log.error("Error monitoring token reuse", e);
        }
    }
}