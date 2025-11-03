package com.strade.auth_app.exception;

/**
 * Exception for MFA-related errors
 */
public class MfaException extends AuthException {

    public MfaException(ErrorCode errorCode) {
        super(errorCode);
    }

    public MfaException(ErrorCode errorCode, String message) {
        super(errorCode, message);
    }

    public MfaException(ErrorCode errorCode, String message, Throwable cause) {
        super(errorCode, message, cause);
    }

    public MfaException(ErrorCode errorCode, Throwable cause) {
        super(errorCode, String.valueOf(cause));
    }
}
