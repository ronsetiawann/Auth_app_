package com.strade.auth_app.exception;
/**
 * Exception for rate limiting
 */
public class RateLimitException extends AuthException {

    private final long retryAfterSeconds;

    public RateLimitException(ErrorCode errorCode, long retryAfterSeconds) {
        super(errorCode);
        this.retryAfterSeconds = retryAfterSeconds;
    }

    public RateLimitException(ErrorCode errorCode, String message, long retryAfterSeconds) {
        super(errorCode, message);
        this.retryAfterSeconds = retryAfterSeconds;
    }

    public long getRetryAfterSeconds() {
        return retryAfterSeconds;
    }
}
