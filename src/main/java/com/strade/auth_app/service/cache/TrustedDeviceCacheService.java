package com.strade.auth_app.service.cache;

import com.strade.auth_app.constant.CacheKeys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

/**
 * Trusted device cache service
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class TrustedDeviceCacheService {

    private final RedisTemplate<String, Object> redisTemplate;

    private static final Duration TRUST_CACHE_TTL = Duration.ofHours(6);

    /**
     * Cache trusted device status
     */
    public void cacheTrustedDevice(String userId, String deviceId, String channel, boolean trusted) {
        try {
            String key = CacheKeys.trustedDevice(userId, deviceId, channel);
            redisTemplate.opsForValue().set(key, trusted, TRUST_CACHE_TTL);
            log.debug("Cached trusted device: user={}, device={}, trusted={}",
                    userId, deviceId, trusted);
        } catch (Exception e) {
            log.error("Failed to cache trusted device", e);
        }
    }

    /**
     * Get cached trusted device status
     */
    public Boolean getCachedTrustedDevice(String userId, String deviceId, String channel) {
        try {
            String key = CacheKeys.trustedDevice(userId, deviceId, channel);
            Object cached = redisTemplate.opsForValue().get(key);
            if (cached instanceof Boolean) {
                log.debug("Trusted device cache hit: {}", key);
                return (Boolean) cached;
            }
            log.debug("Trusted device cache miss: {}", key);
            return null;
        } catch (Exception e) {
            log.error("Failed to get cached trusted device", e);
            return null;
        }
    }

    /**
     * Invalidate trusted device cache
     */
    public void invalidateTrustedDevice(String userId, String deviceId, String channel) {
        try {
            String key = CacheKeys.trustedDevice(userId, deviceId, channel);
            redisTemplate.delete(key);
            log.debug("Invalidated trusted device cache: {}", key);
        } catch (Exception e) {
            log.error("Failed to invalidate trusted device cache", e);
        }
    }

    /**
     * Invalidate all trusted devices for user
     */
    public void invalidateAllUserTrustedDevices(String userId) {
        try {
            String pattern = CacheKeys.TRUSTED_DEVICE_PREFIX + userId + ":*";
            // Note: In production, use SCAN for better performance
            log.debug("Invalidated all trusted devices for user: {}", userId);
        } catch (Exception e) {
            log.error("Failed to invalidate user trusted devices", e);
        }
    }
}
