package com.strade.auth_app.exception;

/**
 * Exception for device-related errors
 */
public class DeviceException extends AuthException {

    public DeviceException(ErrorCode errorCode) {
        super(errorCode);
    }

    public DeviceException(ErrorCode errorCode, String message) {
        super(errorCode, message);
    }

    public DeviceException(ErrorCode errorCode, String message, Throwable cause) {
        super(errorCode, message, cause);
    }
}
