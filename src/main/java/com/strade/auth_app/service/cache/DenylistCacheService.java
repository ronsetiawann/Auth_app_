package com.strade.auth_app.service.cache;

import com.strade.auth_app.constant.CacheKeys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.concurrent.TimeUnit;

/**
 * Token denylist cache service
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class DenylistCacheService {

    private final RedisTemplate<String, Object> redisTemplate;

    /**
     * Add JTI to denylist with expiration
     */
    public void denyJti(String jti, LocalDateTime expiresAt) {
        try {
            String key = CacheKeys.denyJti(jti);
            long ttlSeconds = Duration.between(LocalDateTime.now(), expiresAt).getSeconds();

            if (ttlSeconds > 0) {
                redisTemplate.opsForValue().set(key, "denied", ttlSeconds, TimeUnit.SECONDS);
                log.debug("Added JTI to denylist: {} (TTL: {}s)", jti, ttlSeconds);
            }
        } catch (Exception e) {
            log.error("Failed to deny JTI", e);
        }
    }

    /**
     * Check if JTI is denied
     */
    public boolean isJtiDenied(String jti) {
        try {
            String key = CacheKeys.denyJti(jti);
            Boolean exists = redisTemplate.hasKey(key);

            if (Boolean.TRUE.equals(exists)) {
                log.debug("JTI is denied: {}", jti);
                return true;
            }
            return false;
        } catch (Exception e) {
            log.error("Failed to check JTI denylist", e);
            return false;
        }
    }

    /**
     * Remove JTI from denylist (rarely used)
     */
    public void removeDeniedJti(String jti) {
        try {
            String key = CacheKeys.denyJti(jti);
            redisTemplate.delete(key);
            log.debug("Removed JTI from denylist: {}", jti);
        } catch (Exception e) {
            log.error("Failed to remove JTI from denylist", e);
        }
    }
}
