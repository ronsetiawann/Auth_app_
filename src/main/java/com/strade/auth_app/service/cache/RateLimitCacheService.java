package com.strade.auth_app.service.cache;

import com.strade.auth_app.constant.CacheKeys;
import com.strade.auth_app.exception.ErrorCode;
import com.strade.auth_app.exception.RateLimitException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

/**
 * Rate limit cache service
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class RateLimitCacheService {

    private final RedisTemplate<String, Object> redisTemplate;

    /**
     * Check and increment rate limit
     *
     * @param type Rate limit type (login, otp, etc.)
     * @param identifier Identifier (userId, IP, etc.)
     * @param maxAttempts Maximum attempts allowed
     * @param windowSeconds Time window in seconds
     * @throws RateLimitException if limit exceeded
     */
    public void checkAndIncrement(
            String type,
            String identifier,
            int maxAttempts,
            long windowSeconds
    ) {
        String key = CacheKeys.rateLimit(type, identifier);

        try {
            // Get current count
            Object value = redisTemplate.opsForValue().get(key);
            Integer count = value instanceof Integer ? (Integer) value : 0;

            if (count >= maxAttempts) {
                Long ttl = redisTemplate.getExpire(key, TimeUnit.SECONDS);
                long retryAfter = ttl != null && ttl > 0 ? ttl : windowSeconds;

                log.warn("Rate limit exceeded: type={}, identifier={}, count={}",
                        type, identifier, count);

                throw new RateLimitException(
                        ErrorCode.RATE_LIMIT_EXCEEDED,
                        "Rate limit exceeded. Try again in " + retryAfter + " seconds",
                        retryAfter
                );
            }

            // Increment counter
            redisTemplate.opsForValue().increment(key);

            // Set expiration on first attempt
            if (count == 0) {
                redisTemplate.expire(key, windowSeconds, TimeUnit.SECONDS);
            }

            log.debug("Rate limit check: type={}, identifier={}, count={}/{}",
                    type, identifier, count + 1, maxAttempts);

        } catch (RateLimitException e) {
            throw e;
        } catch (Exception e) {
            log.error("Failed to check rate limit", e);
            // Don't block on cache failure
        }
    }

    /**
     * Reset rate limit counter
     */
    public void reset(String type, String identifier) {
        try {
            String key = CacheKeys.rateLimit(type, identifier);
            redisTemplate.delete(key);
            log.debug("Reset rate limit: type={}, identifier={}", type, identifier);
        } catch (Exception e) {
            log.error("Failed to reset rate limit", e);
        }
    }

    /**
     * Get remaining attempts
     */
    public int getRemainingAttempts(String type, String identifier, int maxAttempts) {
        try {
            String key = CacheKeys.rateLimit(type, identifier);
            Object value = redisTemplate.opsForValue().get(key);
            Integer count = value instanceof Integer ? (Integer) value : 0;
            return Math.max(0, maxAttempts - count);
        } catch (Exception e) {
            log.error("Failed to get remaining attempts", e);
            return maxAttempts;
        }
    }
}
