package com.strade.auth_app.repository.procedure;

import com.strade.auth_app.repository.procedure.dto.FirebaseLoginProcedureResult;
import com.strade.auth_app.repository.procedure.dto.LoginProcedureResult;

import java.util.UUID;

/**
 * Repository for authentication-related stored procedures
 */
public interface AuthProcedureRepository {

    /**
     * Execute SelectUser_Logon stored procedure
     *
     * @param userId User ID
     * @param password User password
     * @param channel Channel (OS, WB, AD, .etc)
     * @param appVersion Application version
     * @param serverNo Server number
     * @param terminalId Terminal ID
     * @param appCode Application code
     * @param deviceId Device fingerprint
     * @param userAgent User agent string
     * @param mfaEnforced MFA enforcement flag (from application config)
     * @return Login result
     */
    LoginProcedureResult selectUserLogon(
            String userId,
            String password,
            String channel,
            String appVersion,
            Integer serverNo,
            String terminalId,
            String appCode,
            String deviceId,
            String userAgent,
            Boolean mfaEnforced
    );

    /**
     * Execute LoginIDXMobile stored procedure (v2.3)
     *
     * @param firebaseToken Firebase authentication token
     * @param userId User ID
     * @param terminal Terminal identifier
     * @param channel Channel (OS, WB, AD, .etc)
     * @param version App version
     * @param deviceId Device fingerprint
     * @param userAgent User agent
     * @param ipAddress IP address
     * @param mfaEnforced MFA enforcement flag
     * @return Firebase login result
     */
    FirebaseLoginProcedureResult loginIdxMobile(
            String firebaseToken,
            String userId,
            String terminal,
            String channel,
            String version,
            String deviceId,
            String userAgent,
            String ipAddress,
            Boolean mfaEnforced
    );

    /**
     * Execute updateUserLoginSuccess stored procedure
     */
    void updateUserLoginSuccess(
            String userId,
            String lastLoginSuccess,
            Integer serverNumber,
            String terminalId,
            UUID sessionId,
            String jwtKid,
            String jwtJti,
            String ip,
            String userAgent
    );

    /**
     * Execute updateUserLoginFail stored procedure
     */
    void updateUserLoginFail(
            String userId,
            Integer maxLoginRetry,
            String lastLoginFail
    );
}
