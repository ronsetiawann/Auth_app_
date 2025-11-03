package com.strade.auth_app.service;

import com.strade.auth_app.entity.AuthEventLog;
import com.strade.auth_app.repository.jpa.AuthEventLogRepository;
import com.strade.auth_app.util.JsonUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Event logging service for audit trail
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class EventLogService {

    private final AuthEventLogRepository eventLogRepository;

    /**
     * Log authentication event
     * Async to avoid blocking main flow
     */
    @Async
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void logEvent(
            String userId,
            UUID sessionId,
            String eventType,
            String reason
    ) {
        logEvent(userId, sessionId, eventType, reason, null);
    }

    /**
     * Log authentication event with metadata
     */
    @Async
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void logEvent(
            String userId,
            UUID sessionId,
            String eventType,
            String reason,
            Map<String, Object> metadata
    ) {
        try {
            AuthEventLog eventLog = AuthEventLog.builder()
                    .eventId(UUID.randomUUID())
                    .eventTime(LocalDateTime.now())
                    .userId(userId)
                    .sessionId(sessionId)
                    .eventType(eventType)
                    .reason(reason)
                    .metadata(metadata != null ? JsonUtil.toJson(metadata) : null)
                    .build();

            eventLogRepository.save(eventLog);

            log.debug("Event logged: type={}, userId={}, sessionId={}",
                    eventType, userId, sessionId);

        } catch (Exception e) {
            // Don't throw - logging should not break main flow
            log.error("Failed to log event: type={}, userId={}", eventType, userId, e);
        }
    }

    /**
     * Get events for user
     */
    public List<AuthEventLog> getUserEvents(String userId) {
        return eventLogRepository.findByUserIdOrderByEventTimeDesc(userId);
    }

    /**
     * Get events for session
     */
    public List<AuthEventLog> getSessionEvents(UUID sessionId) {
        return eventLogRepository.findBySessionIdOrderByEventTimeAsc(sessionId);
    }

    /**
     * Get events by type since timestamp
     */
    public List<AuthEventLog> getEventsByType(String eventType, LocalDateTime since) {
        return eventLogRepository.findByEventTypeAndEventTimeAfter(eventType, since);
    }
}
