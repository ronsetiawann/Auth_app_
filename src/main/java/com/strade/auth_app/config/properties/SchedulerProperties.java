package com.strade.auth_app.config.properties;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Scheduler configuration properties
 * Control enable/disable untuk setiap scheduler
 */
@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix = "app.scheduler")
public class SchedulerProperties {

    private boolean enabled = true; // Master switch

    private TokenCleanup tokenCleanup = new TokenCleanup();
    private SessionCleanup sessionCleanup = new SessionCleanup();
    private SecurityMonitor securityMonitor = new SecurityMonitor();
    private NotificationProcessor notificationProcessor = new NotificationProcessor();
    private HealthCheck healthCheck = new HealthCheck();

    @Getter
    @Setter
    public static class TokenCleanup {
        private boolean enabled = true;
        private boolean expiredDenylist = true;
        private boolean revokedRefreshTokens = true;
        private boolean expiredOtpChallenges = true;
        private boolean oldOtpChallenges = true;
        private boolean comprehensiveCleanup = true;
    }

    @Getter
    @Setter
    public static class SessionCleanup {
        private boolean enabled = true;
        private boolean markInactive = true;
        private boolean cleanupExpired = true;
    }

    @Getter
    @Setter
    public static class SecurityMonitor {
        private boolean enabled = true;
        private boolean monitor = true;
        private boolean loginFailures = true;
        private boolean tokenReuse = true;
    }

    @Getter
    @Setter
    public static class NotificationProcessor {
        private boolean enabled = true;
        private boolean processPending = true;
        private boolean cleanupOld = true;
    }

    @Getter
    @Setter
    public static class HealthCheck {
        private boolean enabled = true;
        private boolean database = true;
        private boolean redis = true;
    }
}
