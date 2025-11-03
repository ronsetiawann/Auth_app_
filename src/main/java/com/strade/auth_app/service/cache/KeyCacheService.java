package com.strade.auth_app.service.cache;

import com.strade.auth_app.constant.CacheKeys;
import com.strade.auth_app.entity.KeyStore;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

/**
 * JWT key cache service
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class KeyCacheService {

    private final RedisTemplate<String, Object> redisTemplate;

    private static final Duration KEY_CACHE_TTL = Duration.ofHours(24);

    /**
     * Cache JWT public key
     */
    public void cachePublicKey(String kid, KeyStore keyStore) {
        try {
            String key = CacheKeys.jwtPublicKey(kid);
            redisTemplate.opsForValue().set(key, keyStore.getPublicKeyPem(), KEY_CACHE_TTL);
            log.debug("Cached public key: {}", kid);
        } catch (Exception e) {
            log.error("Failed to cache public key", e);
        }
    }

    /**
     * Get cached public key
     */
    public String getCachedPublicKey(String kid) {
        try {
            String key = CacheKeys.jwtPublicKey(kid);
            Object cached = redisTemplate.opsForValue().get(key);
            if (cached instanceof String) {
                log.debug("Public key cache hit: {}", kid);
                return (String) cached;
            }
            log.debug("Public key cache miss: {}", kid);
            return null;
        } catch (Exception e) {
            log.error("Failed to get cached public key", e);
            return null;
        }
    }

    /**
     * Cache active key ID
     */
    public void cacheActiveKeyId(String kid) {
        try {
            redisTemplate.opsForValue().set(CacheKeys.ACTIVE_KEY, kid, KEY_CACHE_TTL);
            log.debug("Cached active key ID: {}", kid);
        } catch (Exception e) {
            log.error("Failed to cache active key ID", e);
        }
    }

    /**
     * Get cached active key ID
     */
    public String getCachedActiveKeyId() {
        try {
            Object cached = redisTemplate.opsForValue().get(CacheKeys.ACTIVE_KEY);
            if (cached instanceof String) {
                return (String) cached;
            }
            return null;
        } catch (Exception e) {
            log.error("Failed to get cached active key ID", e);
            return null;
        }
    }

    /**
     * Invalidate all key caches
     */
    public void invalidateAllKeys() {
        try {
            String pattern = CacheKeys.JWT_PUBLIC_KEY_PREFIX + "*";
            redisTemplate.delete(CacheKeys.ACTIVE_KEY);
            log.debug("Invalidated all key caches");
        } catch (Exception e) {
            log.error("Failed to invalidate key caches", e);
        }
    }
}
