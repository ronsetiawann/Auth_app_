package com.strade.auth_app.exception;

/**
 * Exception for token-related errors
 */
public class TokenException extends AuthException {

    public TokenException(ErrorCode errorCode) {
        super(errorCode);
    }

    public TokenException(ErrorCode errorCode, String message) {
        super(errorCode, message);
    }

    public TokenException(ErrorCode errorCode, String message, Throwable cause) {
        super(errorCode, message, cause);
    }

    public TokenException(ErrorCode errorCode, Throwable cause) {
        super(errorCode, String.valueOf(cause));
    }
}
