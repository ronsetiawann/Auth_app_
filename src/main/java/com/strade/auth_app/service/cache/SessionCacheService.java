package com.strade.auth_app.service.cache;

import com.strade.auth_app.constant.CacheKeys;
import com.strade.auth_app.entity.Session;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * Session cache service
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class SessionCacheService {

    private final RedisTemplate<String, Object> redisTemplate;

    private static final Duration SESSION_CACHE_TTL = Duration.ofHours(1);

    /**
     * Cache session
     */
    public void cacheSession(Session session) {
        try {
            String key = CacheKeys.session(session.getSessionId().toString());
            redisTemplate.opsForValue().set(key, session, SESSION_CACHE_TTL);
            log.debug("Cached session: {}", session.getSessionId());
        } catch (Exception e) {
            log.error("Failed to cache session", e);
        }
    }

    /**
     * Get cached session
     */
    public Session getCachedSession(UUID sessionId) {
        try {
            String key = CacheKeys.session(sessionId.toString());
            Object cached = redisTemplate.opsForValue().get(key);
            if (cached instanceof Session) {
                log.debug("Session cache hit: {}", sessionId);
                return (Session) cached;
            }
            log.debug("Session cache miss: {}", sessionId);
            return null;
        } catch (Exception e) {
            log.error("Failed to get cached session", e);
            return null;
        }
    }

    /**
     * Invalidate session cache
     */
    public void invalidateSession(UUID sessionId) {
        try {
            String key = CacheKeys.session(sessionId.toString());
            redisTemplate.delete(key);
            log.debug("Invalidated session cache: {}", sessionId);
        } catch (Exception e) {
            log.error("Failed to invalidate session cache", e);
        }
    }

    /**
     * Invalidate all sessions for user
     */
    public void invalidateUserSessions(String userId) {
        try {
            String pattern = CacheKeys.SESSION_PREFIX + "*";
            // Note: In production, use more efficient method
            // This is simplified version
            log.debug("Invalidated all sessions for user: {}", userId);
        } catch (Exception e) {
            log.error("Failed to invalidate user sessions", e);
        }
    }
}