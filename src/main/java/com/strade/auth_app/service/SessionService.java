package com.strade.auth_app.service;

import com.strade.auth_app.constant.AppConstants;
import com.strade.auth_app.dto.response.SessionResponse;
import com.strade.auth_app.entity.Session;
import com.strade.auth_app.exception.AuthException;
import com.strade.auth_app.exception.ErrorCode;
import com.strade.auth_app.repository.jpa.SessionRepository;
import com.strade.auth_app.service.cache.SessionCacheService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Session management service
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class SessionService {

    private final SessionRepository sessionRepository;
    private final SessionCacheService sessionCacheService;

    /**
     * Get session by ID
     */
    public Session getSession(UUID sessionId) {
        // Try cache first
        Session cached = sessionCacheService.getCachedSession(sessionId);
        if (cached != null) {
            return cached;
        }

        // Load from database
        Session session = sessionRepository.findBySessionId(sessionId)
                .orElseThrow(() -> new AuthException(
                        ErrorCode.SESSION_NOT_FOUND,
                        "Session not found"
                ));

        // Cache it
        sessionCacheService.cacheSession(session);

        return session;
    }

    /**
     * Get session details
     */
    public SessionResponse getSessionDetails(UUID sessionId) {
        Session session = getSession(sessionId);
        return mapToResponse(session);
    }

    /**
     * List active sessions for user
     */
    public List<SessionResponse> listActiveSessions(String userId) {
        List<Session> sessions = sessionRepository.findActiveSessionsByUserId(userId);
        return sessions.stream()
                .map(this::mapToResponse)
                .collect(Collectors.toList());
    }

    /**
     * Count active sessions for user
     */
    public long countActiveSessions(String userId) {
        return sessionRepository.countActiveSessionsByUserId(userId);
    }

    /**
     * Update session last seen timestamp
     */
    @Transactional
    public void updateLastSeen(UUID sessionId) {
        sessionRepository.findBySessionId(sessionId).ifPresent(session -> {
            session.setLastSeenAt(LocalDateTime.now());
            sessionRepository.save(session);
            sessionCacheService.cacheSession(session);
        });
    }

    /**
     * Check if session is valid
     */
    public boolean isSessionValid(UUID sessionId) {
        try {
            Session session = getSession(sessionId);

            // Check status
            if (session.getStatus() != AppConstants.SESSION_STATUS_ACTIVE) {
                return false;
            }

            // Check expiration
            if (session.getExpiresAt() != null && session.getExpiresAt().isBefore(LocalDateTime.now())) {
                return false;
            }

            return true;
        } catch (AuthException e) {
            return false;
        }
    }

    /**
     * Map Session entity to response DTO
     */
    private SessionResponse mapToResponse(Session session) {
        return SessionResponse.builder()
                .sessionId(session.getSessionId())
                .userId(session.getUserId())
                .channel(session.getChannel())
                .deviceId(session.getDeviceId())
                .deviceName(generateDeviceName(session)) // Generate dari userAgent/channel
                .ipAddress(session.getIpAddress())
                .status(session.getStatus())
                .mfaRequired(session.getStatus() == AppConstants.SESSION_STATUS_PENDING)
                .mfaMethod(session.getMfaMethod())
                .createdAt(session.getCreatedAt())
                .lastSeenAt(session.getLastSeenAt())
                .expiresAt(session.getExpiresAt())
                .build();
    }

    /**
     * Generate user-friendly device name from session data
     */
    private String generateDeviceName(Session session) {
        String userAgent = session.getUserAgent();

        // Try to extract from User-Agent
        if (userAgent != null && !userAgent.isEmpty()) {
            String lower = userAgent.toLowerCase();

            if (lower.contains("chrome")) {
                return "Chrome Browser";
            } else if (lower.contains("firefox")) {
                return "Firefox Browser";
            } else if (lower.contains("safari") && !lower.contains("chrome")) {
                return "Safari Browser";
            } else if (lower.contains("edge")) {
                return "Edge Browser";
            } else if (lower.contains("android")) {
                return "Android Device";
            } else if (lower.contains("iphone")) {
                return "iPhone";
            } else if (lower.contains("ipad")) {
                return "iPad";
            } else if (lower.contains("windows")) {
                return "Windows PC";
            } else if (lower.contains("mac")) {
                return "Mac";
            } else if (lower.contains("linux")) {
                return "Linux PC";
            }
        }

        // Fallback to channel-based name
        String channel = session.getChannel();
        if (channel != null) {
            return switch (channel.toUpperCase()) {
                case "AD" -> "Android Device";
                case "OS" -> "iOS Device";
                case "WB" -> "Web Browser";
                case "RT" -> "Desktop Application";
                case "OT" -> "Tablet";
                case "BB" -> "BlackBerry";
                default -> "Unknown Device";
            };
        }

        return "Unknown Device";
    }
}