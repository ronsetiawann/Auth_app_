package com.strade.auth_app.exception;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

/**
 * Centralized error codes for the authentication service
 */
@Getter
@RequiredArgsConstructor
public enum ErrorCode {

    // ========================================
    // GENERAL ERRORS (1000-1099)
    // ========================================
    INTERNAL_SERVER_ERROR(1000, "Internal server error", HttpStatus.INTERNAL_SERVER_ERROR),
    USER_LOCKED(1001, "User account is locked", HttpStatus.FORBIDDEN),
    USER_DISABLED(1002, "User account is disabled", HttpStatus.FORBIDDEN),
    USER_EXPIRED(1003, "User account is expired", HttpStatus.FORBIDDEN),
    TERMINAL_NOT_ALLOWED(1004, "Terminal not allowed", HttpStatus.FORBIDDEN),
    PASSWORD_EXPIRED(1005, "Password has expired", HttpStatus.UNAUTHORIZED),
    INVALID_CREDENTIALS(1006, "Invalid username or password", HttpStatus.UNAUTHORIZED),
    VERSION_MISMATCH(1007, "Application version mismatch - update required", HttpStatus.UPGRADE_REQUIRED),
    CHANNEL_NOT_ALLOWED(1008, "Channel not allowed for this user", HttpStatus.FORBIDDEN),

    DATABASE_ERROR(1010, "Database operation failed", HttpStatus.INTERNAL_SERVER_ERROR),
    INVALID_REQUEST(1011, "Invalid request parameters", HttpStatus.BAD_REQUEST),
    VALIDATION_ERROR(1012, "Request validation failed", HttpStatus.BAD_REQUEST),
    RESOURCE_NOT_FOUND(1013, "Resource not found", HttpStatus.NOT_FOUND),

    // ========================================
    // AUTHENTICATION ERRORS (2000-2099)
    // ========================================
    USER_NOT_FOUND(2000, "User not found", HttpStatus.NOT_FOUND),
    AUTHENTICATION_FAILED(2001, "Authentication failed", HttpStatus.UNAUTHORIZED),
    ACCOUNT_NOT_ACTIVE(2002, "User account is not active", HttpStatus.FORBIDDEN),
    INSUFFICIENT_PERMISSIONS(2003, "Insufficient permissions", HttpStatus.FORBIDDEN),

    // ========================================
    // SERVER ERRORS (3000-3099)
    // ========================================
    SERVER_NOT_READY(3000, "Server not ready - outside operating hours", HttpStatus.SERVICE_UNAVAILABLE),
    MAINTENANCE_MODE(3001, "System under maintenance", HttpStatus.SERVICE_UNAVAILABLE),

    // ========================================
    // TOKEN ERRORS (3100-3199)
    // ========================================
    TOKEN_INVALID(3100, "Invalid token", HttpStatus.UNAUTHORIZED),
    TOKEN_EXPIRED(3101, "Token has expired", HttpStatus.UNAUTHORIZED),
    TOKEN_REVOKED(3102, "Token has been revoked", HttpStatus.UNAUTHORIZED),
    TOKEN_MALFORMED(3103, "Malformed token", HttpStatus.BAD_REQUEST),
    TOKEN_SIGNATURE_INVALID(3104, "Invalid token signature", HttpStatus.UNAUTHORIZED),
    TOKEN_REUSE_DETECTED(3105, "Token reuse detected - security breach", HttpStatus.FORBIDDEN),

    REFRESH_TOKEN_INVALID(3110, "Invalid refresh token", HttpStatus.UNAUTHORIZED),
    REFRESH_TOKEN_EXPIRED(3111, "Refresh token has expired", HttpStatus.UNAUTHORIZED),
    REFRESH_TOKEN_REVOKED(3112, "Refresh token has been revoked", HttpStatus.UNAUTHORIZED),

    // ========================================
    // SESSION ERRORS (4000-4099)
    // ========================================
    SESSION_NOT_FOUND(4000, "Session not found", HttpStatus.NOT_FOUND),
    SESSION_EXPIRED(4001, "Session has expired", HttpStatus.UNAUTHORIZED),
    SESSION_INACTIVE(4002, "Session is not active", HttpStatus.UNAUTHORIZED),
    SESSION_REVOKED(4003, "Session has been revoked", HttpStatus.UNAUTHORIZED),
    SESSION_LIMIT_REACHED(4004, "Maximum active sessions reached", HttpStatus.FORBIDDEN),

    MFA_REQUIRED(4100, "Multi-factor authentication required", HttpStatus.UNAUTHORIZED),
    MFA_PENDING(4101, "MFA verification pending", HttpStatus.ACCEPTED),

    // ========================================
    // MFA ERRORS (5000-5099)
    // ========================================
    MFA_NOT_ENABLED(5000, "MFA is not enabled for this user", HttpStatus.BAD_REQUEST),
    MFA_ALREADY_ENABLED(5001, "MFA is already enabled", HttpStatus.CONFLICT),
    MFA_SETUP_REQUIRED(5002, "MFA setup required", HttpStatus.PRECONDITION_REQUIRED),

    // OTP Errors (5010-5029)
    OTP_INVALID(5010, "Invalid OTP code", HttpStatus.BAD_REQUEST),
    OTP_EXPIRED(5011, "OTP has expired", HttpStatus.BAD_REQUEST),
    OTP_NOT_FOUND(5012, "OTP challenge not found", HttpStatus.NOT_FOUND),
    OTP_ALREADY_USED(5013, "OTP code has already been used", HttpStatus.BAD_REQUEST),
    OTP_MAX_ATTEMPTS(5014, "Maximum OTP attempts exceeded", HttpStatus.TOO_MANY_REQUESTS),
    OTP_GENERATION_FAILED(5015, "Failed to generate OTP", HttpStatus.INTERNAL_SERVER_ERROR),
    OTP_SEND_FAILED(5016, "Failed to send OTP", HttpStatus.INTERNAL_SERVER_ERROR),

    // TOTP Errors (5030-5049)
    TOTP_INVALID(5030, "Invalid TOTP code", HttpStatus.BAD_REQUEST),
    TOTP_SETUP_FAILED(5031, "TOTP setup failed", HttpStatus.INTERNAL_SERVER_ERROR),
    TOTP_NOT_SETUP(5032, "TOTP is not set up", HttpStatus.BAD_REQUEST),
    TOTP_ALREADY_USED(5033, "TOTP code has already been used", HttpStatus.BAD_REQUEST),
    TOTP_REPLAY_DETECTED(5034, "TOTP replay attack detected", HttpStatus.FORBIDDEN),

    // Backup Code Errors (5050-5059)
    BACKUP_CODE_INVALID(5050, "Invalid backup code", HttpStatus.BAD_REQUEST),
    BACKUP_CODE_ALREADY_USED(5051, "Backup code has already been used", HttpStatus.BAD_REQUEST),
    BACKUP_CODE_EXHAUSTED(5052, "All backup codes have been used", HttpStatus.FORBIDDEN),

    // ========================================
    // DEVICE ERRORS (6000-6099)
    // ========================================
    DEVICE_NOT_TRUSTED(6000, "Device is not trusted", HttpStatus.UNAUTHORIZED),
    DEVICE_LIMIT_REACHED(6001, "Maximum trusted devices limit reached", HttpStatus.FORBIDDEN),
    DEVICE_NOT_FOUND(6002, "Trusted device not found", HttpStatus.NOT_FOUND),
    DEVICE_ALREADY_TRUSTED(6003, "Device is already trusted", HttpStatus.CONFLICT),

    // ========================================
    // FIREBASE ERRORS (7000-7099)
    // ========================================
    FIREBASE_TOKEN_INVALID(7000, "Invalid Firebase token", HttpStatus.UNAUTHORIZED),
    FIREBASE_TOKEN_EXPIRED(7001, "Firebase token has expired", HttpStatus.UNAUTHORIZED),
    FIREBASE_AUTH_FAILED(7002, "Firebase authentication failed", HttpStatus.UNAUTHORIZED),
    FIREBASE_USER_NOT_FOUND(7003, "Firebase user not found", HttpStatus.NOT_FOUND),
    FIREBASE_SERVICE_ERROR(7004, "Firebase service error", HttpStatus.INTERNAL_SERVER_ERROR),

    // ========================================
    // NOTIFICATION ERRORS (8000-8099)
    // ========================================
    NOTIFICATION_SEND_FAILED(8000, "Failed to send notification", HttpStatus.INTERNAL_SERVER_ERROR),
    EMAIL_SEND_FAILED(8001, "Failed to send email", HttpStatus.INTERNAL_SERVER_ERROR),
    SMS_SEND_FAILED(8002, "Failed to send SMS", HttpStatus.INTERNAL_SERVER_ERROR),
    WHATSAPP_SEND_FAILED(8003, "Failed to send WhatsApp message", HttpStatus.INTERNAL_SERVER_ERROR),
    INVALID_DESTINATION(8010, "Invalid notification destination", HttpStatus.BAD_REQUEST),

    // ========================================
    // RATE LIMIT ERRORS (9000-9099)
    // ========================================
    RATE_LIMIT_EXCEEDED(9000, "Rate limit exceeded", HttpStatus.TOO_MANY_REQUESTS),
    TOO_MANY_LOGIN_ATTEMPTS(9001, "Too many login attempts", HttpStatus.TOO_MANY_REQUESTS),
    TOO_MANY_OTP_REQUESTS(9002, "Too many OTP requests", HttpStatus.TOO_MANY_REQUESTS);

    private final int code;
    private final String message;
    private final HttpStatus httpStatus;

    /**
     * Constructor for backward compatibility (without HttpStatus)
     */
    ErrorCode(int code, String message) {
        this.code = code;
        this.message = message;
        this.httpStatus = HttpStatus.INTERNAL_SERVER_ERROR; // Default
    }
}