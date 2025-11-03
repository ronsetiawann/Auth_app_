package com.strade.auth_app.service;

import com.strade.auth_app.entity.LogLogin;
import com.strade.auth_app.entity.User;
import com.strade.auth_app.exception.AuthException;
import com.strade.auth_app.exception.ErrorCode;
import com.strade.auth_app.repository.jpa.LogLoginRepository;
import com.strade.auth_app.repository.jpa.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalTime;

/**
 * Login Validation Service
 * Replicate business logic dari SP lama (dbo.SelectUser_Logon)
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class LoginValidationService {

    private final UserRepository userRepository;
    private final LogLoginRepository logLoginRepository;

    @Value("${app.security.broker-login-hour:1}")
    private Integer minLoginHour;

    @Value("${app.security.broker-login-minute:0}")
    private Integer minLoginMinute;

    /**
     * Comprehensive login validation
     * Replicates all checks from old SP
     */
    @Transactional
    public void validateLogin(String userId, String password, String terminalId, String channel) {

        // 1. Check server ready (MinLoginHour/Minute)
        validateServerReady();

        // 2. Get user from database
        User user = userRepository.findActiveUserByUserId(userId)
                .orElseThrow(() -> new AuthException(
                        ErrorCode.USER_NOT_FOUND,
                        "Your UserID Not Yet Listed, Login Failed!"
                ));

        // 3. Get login retry info
        LogLogin logLogin = logLoginRepository.findByUserId(userId).orElse(null);

        // 4. Check login retry (locked)
        if (logLogin != null && logLogin.isLocked()) {
            throw new AuthException(
                    ErrorCode.USER_LOCKED,
                    "Your UserID Login Was Blocked, Login Failed!"
            );
        }

        // 5. Check user enabled
        if (!user.isEnabled()) {
            throw new AuthException(
                    ErrorCode.USER_DISABLED,
                    "Your UserID Was Disabled, Login Failed!"
            );
        }

        // 6. Check user expiration
        if (user.isExpired()) {
            throw new AuthException(
                    ErrorCode.USER_EXPIRED,
                    "Your UserID Was Expired, Login Failed!"
            );
        }

        // 7. Check disallowed terminals
        if (user.isTerminalDisallowed(terminalId)) {
            throw new AuthException(
                    ErrorCode.TERMINAL_NOT_ALLOWED,
                    "Your UserID Not Allowed To Login At This \"" + terminalId + "\" Terminal, Login Failed!"
            );
        }

        // 8. Validate password
        if (!validatePassword(password, user.getPassword())) {
            // Increment failure counter
            if (logLogin != null) {
                logLogin.incrementFailure();
                logLoginRepository.save(logLogin);
            }

            throw new AuthException(
                    ErrorCode.INVALID_CREDENTIALS,
                    "Wrong Password, Login Failed!"
            );
        }

        // 9. Check password expiration
        if (user.isPasswordExpired()) {
            throw new AuthException(
                    ErrorCode.PASSWORD_EXPIRED,
                    "Your Password Already Expired, Please Re-Type Your Password!(ChangePassword)"
            );
        }

        // 10. Check AsClient for RT channel
        String normalizedChannel = channel != null ? channel : "RT";
        if (("RT".equals(normalizedChannel) || "IDX".equals(normalizedChannel)) &&
                Boolean.TRUE.equals(user.getAsClient())) {
            throw new AuthException(
                    ErrorCode.CHANNEL_NOT_ALLOWED,
                    "User Online Cannot login from Remote Trading Apps, Login Failed!"
            );
        }

        // 11. Password cannot be empty
        if (password == null || password.isEmpty()) {
            throw new AuthException(
                    ErrorCode.INVALID_REQUEST,
                    "Password Cannot Empty!"
            );
        }

        // All validations passed
        log.info("Login validation passed for user: {}", userId);
    }

    /**
     * Check if server is ready (MinLoginHour/Minute)
     */
    private void validateServerReady() {
        LocalTime now = LocalTime.now();
        LocalTime minLoginTime = LocalTime.of(minLoginHour, minLoginMinute);

        if (now.isBefore(minLoginTime)) {
            throw new AuthException(
                    ErrorCode.SERVER_NOT_READY,
                    "Server not Ready, Login Failed!"
            );
        }
    }

    /**
     * Validate password
     * TODO: Implement proper password hashing (BCrypt, etc)
     */
    private boolean validatePassword(String inputPassword, String dbPassword) {
        // For now, direct comparison
        // TODO: Use BCrypt or proper hashing algorithm
        return inputPassword != null && inputPassword.equals(dbPassword);
    }

    /**
     * Reset login retry counter on successful login
     */
    @Transactional
    public void resetLoginRetry(String userId) {
        logLoginRepository.findByUserId(userId).ifPresent(logLogin -> {
            logLogin.resetRetry();
            logLoginRepository.save(logLogin);
        });
    }

    /**
     * Get login message (last login info)
     */
    public String getLoginMessage(String userId) {
        return logLoginRepository.findByUserId(userId)
                .map(logLogin -> {
                    StringBuilder msg = new StringBuilder();

                    if (logLogin.getLastLoginSuccessTime() != null &&
                            !logLogin.getLastLoginSuccessTime().isEmpty()) {
                        msg.append("Your Last Success Login At : ")
                                .append(logLogin.getLastLoginSuccessTime())
                                .append("\r\n");
                    }

                    if (logLogin.getLastLoginFailTime() != null &&
                            !logLogin.getLastLoginFailTime().isEmpty()) {
                        msg.append("Your Last Fail Login At : ")
                                .append(logLogin.getLastLoginFailTime())
                                .append("\r\n");
                    }

                    return msg.length() > 0 ? msg.toString() : "This Is Your First Time Login!";
                })
                .orElse("This Is Your First Time Login!");
    }
}