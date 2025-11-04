package com.strade.auth_app.repository.procedure;

import com.strade.auth_app.repository.procedure.dto.FirebaseLoginProcedureResult;
import com.strade.auth_app.repository.procedure.dto.LoginProcedureResult;

import java.util.UUID;

/**
 * Repository for authentication stored procedures
 *
 * MINIMAL UPDATE - Added method signatures for new requirements
 */
public interface AuthProcedureRepository {

    /**
     * Execute user login stored procedure
     *
     * ✅ UPDATED: Added minLoginHour and minLoginMinute parameters (12 total)
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
            Boolean mfaEnforced,
            Integer minLoginHour,      // ✅ NEW PARAMETER
            Integer minLoginMinute     // ✅ NEW PARAMETER
    );

    /**
     * ✅ NEW METHOD: Update session with JTI after token generation
     *
     * Calls: Auth.UpdateSessionJti
     *
     * This is called AFTER selectUserLogon returns and tokens are generated.
     * Required because JTI (JWT ID) is only known after token creation.
     */
    void updateSessionJti(
            UUID sessionId,
            String jwtKid,
            String jwtJti
    );

    /**
     * Execute Firebase login stored procedure (IDX Mobile)
     *
     * UNCHANGED
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
     * Update user login success
     *
     * UNCHANGED
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
     * Update user login failure
     *
     * UNCHANGED
     */
    void updateUserLoginFail(
            String userId,
            Integer maxLoginRetry,
            String lastLoginFail
    );
}