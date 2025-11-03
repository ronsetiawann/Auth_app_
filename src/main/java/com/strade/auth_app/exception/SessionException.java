package com.strade.auth_app.exception;

/**
 * Exception for session-related errors
 */
public class SessionException extends AuthException {

    public SessionException(ErrorCode errorCode) {
        super(errorCode);
    }

    public SessionException(ErrorCode errorCode, String message) {
        super(errorCode, message);
    }

    public SessionException(ErrorCode errorCode, String message, Throwable cause) {
        super(errorCode, message, cause);
    }

    public SessionException(ErrorCode errorCode, Throwable cause) {
        super(errorCode, String.valueOf(cause));
    }
}
