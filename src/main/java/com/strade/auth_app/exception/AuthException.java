package com.strade.auth_app.exception;

import lombok.Getter;

/**
 * Base authentication exception
 */
@Getter
public class AuthException extends RuntimeException {

    private final ErrorCode errorCode;
    private final int customCode; // For legacy SP error codes
    private final Object details;

    /**
     * Constructor with ErrorCode enum
     */
    public AuthException(ErrorCode errorCode) {
        super(errorCode.getMessage());
        this.errorCode = errorCode;
        this.customCode = errorCode.getCode();
        this.details = null;
    }

    /**
     * Constructor with ErrorCode and custom message
     */
    public AuthException(ErrorCode errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
        this.customCode = errorCode.getCode();
        this.details = null;
    }

    /**
     * Constructor with ErrorCode, message, and cause
     */
    public AuthException(ErrorCode errorCode, String message, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
        this.customCode = errorCode.getCode();
        this.details = null;
    }

    /**
     * Constructor with ErrorCode, message, and details
     */
    public AuthException(ErrorCode errorCode, String message, Object details) {
        super(message);
        this.errorCode = errorCode;
        this.customCode = errorCode.getCode();
        this.details = details;
    }

    /**
     * Legacy constructor - DEPRECATED
     * For backward compatibility with old SP error codes
     *
     * @deprecated Use constructor with ErrorCode enum instead
     */
    @Deprecated
    public AuthException(ErrorCode errorCode, String message, int legacyCode) {
        super(message);
        this.errorCode = errorCode;
        this.customCode = legacyCode; // Override with legacy code if different
        this.details = null;
    }

    /**
     * Get the error code (returns custom code if set, otherwise ErrorCode's code)
     */
    public int getCode() {
        return customCode;
    }

    /**
     * Get HTTP status from ErrorCode
     */
    public org.springframework.http.HttpStatus getHttpStatus() {
        return errorCode.getHttpStatus();
    }
}