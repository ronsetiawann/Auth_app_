package com.strade.auth_app.repository.procedure.impl;

import com.strade.auth_app.exception.AuthException;
import com.strade.auth_app.exception.ErrorCode;
import com.strade.auth_app.repository.procedure.AuthProcedureRepository;
import com.strade.auth_app.repository.procedure.dto.FirebaseLoginProcedureResult;
import com.strade.auth_app.repository.procedure.dto.LoginProcedureResult;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.SqlParameter;
import org.springframework.jdbc.core.simple.SimpleJdbcCall;
import org.springframework.stereotype.Repository;

import javax.sql.DataSource;
import java.sql.Types;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Implementation of authentication stored procedure calls
 *
 * MINIMAL FIX - Only essential changes from existing code
 */
@Slf4j
@Repository
@RequiredArgsConstructor
public class AuthProcedureRepositoryImpl implements AuthProcedureRepository {

    private final DataSource dataSource;

    /**
     * ✅ FIXED: Added minLoginHour and minLoginMinute parameters (now 12 total)
     */
    @Override
    public LoginProcedureResult selectUserLogon(
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
    ) {
        log.info("=== SelectUser_Logon Parameters ===");
        log.info("UserId: {}", userId);
        log.info("Password: {}", password != null ? "***" : null);
        log.info("Channel: {}", channel);
        log.info("AppVersion: {}", appVersion);
        log.info("ServerNo: {}", serverNo);
        log.info("TerminalId: {}", terminalId);
        log.info("AppCode: {}", appCode);
        log.info("DeviceId: {}", deviceId);
        log.info("UserAgent: {}", userAgent);
        log.info("MfaEnforced: {}", mfaEnforced);
        log.info("MinLoginHour: {}", minLoginHour);        // ✅ NEW
        log.info("MinLoginMinute: {}", minLoginMinute);    // ✅ NEW
        log.info("====================================");

        SimpleJdbcCall jdbcCall = new SimpleJdbcCall(dataSource)
                .withSchemaName("dbo")
                .withProcedureName("SelectUser_Logon_v2")
                .declareParameters(
                        new SqlParameter("UserID", Types.NVARCHAR),
                        new SqlParameter("Password", Types.NVARCHAR),
                        new SqlParameter("Channel", Types.NVARCHAR),
                        new SqlParameter("AppVersion", Types.NVARCHAR),
                        new SqlParameter("ServerNo", Types.INTEGER),
                        new SqlParameter("TerminalID", Types.NVARCHAR),
                        new SqlParameter("AppCode", Types.NVARCHAR),
                        new SqlParameter("DeviceId", Types.NVARCHAR),
                        new SqlParameter("UserAgent", Types.NVARCHAR),
                        new SqlParameter("MfaEnforced", Types.BIT),
                        new SqlParameter("MinLoginHour", Types.INTEGER),
                        new SqlParameter("MinLoginMinute", Types.INTEGER)
                )
                .returningResultSet("#result-set-1", (rs, rowNum) -> {
                    Map<String, Object> row = new java.util.LinkedHashMap<>();
                    int columnCount = rs.getMetaData().getColumnCount();
                    for (int i = 1; i <= columnCount; i++) {
                        String columnName = rs.getMetaData().getColumnName(i);
                        row.put(columnName, rs.getObject(i));
                    }
                    return row;
                });

        Map<String, Object> spResult;

        try {
            spResult = jdbcCall.execute(
                    userId, password, channel, appVersion, serverNo,
                    terminalId, appCode, deviceId, userAgent, mfaEnforced,
                    minLoginHour, minLoginMinute  // ✅ NEW PARAMETERS
            );

            log.info("=== Raw SP Result ===");
            spResult.forEach((key, value) -> {
                log.info("Key: {} = {}", key, value);
                if (value instanceof List) {
                    log.info("  └─ List size: {}", ((List<?>) value).size());
                }
            });
            log.info("=====================");

        } catch (Exception e) {
            log.error("❌ Error executing SelectUser_Logon SP", e);
            log.error("Exception type: {}", e.getClass().getName());
            log.error("Exception message: {}", e.getMessage());
            if (e.getCause() != null) {
                log.error("Cause: {}", e.getCause().getMessage());
            }
            throw new AuthException(
                    ErrorCode.DATABASE_ERROR,
                    "Login procedure execution failed: " + e.getMessage(),
                    e
            );
        }

        // Extract data dari result-set
        Map<String, Object> actualData = extractFirstRow(spResult, "#result-set-1");

        if (actualData == null || actualData.isEmpty()) {
            log.error("❌ No data returned from SP. Raw result: {}", spResult);
            throw new AuthException(
                    ErrorCode.DATABASE_ERROR,
                    "No data returned from login procedure"
            );
        }

        log.info("=== Extracted Data ===");
        actualData.forEach((key, value) -> log.info("{} = {}", key, value));
        log.info("======================");

        // Map hasil ke DTO
        LoginProcedureResult loginResult = mapToLoginResult(actualData);

        log.info("=== Mapped Result ===");
        log.info("IsLoginSuccess: {}", loginResult.getIsLoginSuccess());
        log.info("LoginMessage: {}", loginResult.getLoginMessage());
        log.info("ErrCode: {}", loginResult.getErrCode());
        log.info("SessionId: {}", loginResult.getSessionId());
        log.info("MfaRequired: {}", loginResult.getMfaRequired());
        log.info("=====================");

        return loginResult;
    }

    /**
     * ✅ NEW METHOD: Update session with JTI after token generation
     */
    @Override
    public void updateSessionJti(
            UUID sessionId,
            String jwtKid,
            String jwtJti
    ) {
        log.debug("Calling Auth.UpdateSessionJti for sessionId: {}", sessionId);

        SimpleJdbcCall jdbcCall = new SimpleJdbcCall(dataSource)
                .withSchemaName("Auth")
                .withProcedureName("UpdateSessionJti")
                .declareParameters(
                        new SqlParameter("SessionId", Types.VARCHAR),
                        new SqlParameter("JwtKid", Types.NVARCHAR),
                        new SqlParameter("JwtJti", Types.NVARCHAR)
                );

        try {
            jdbcCall.execute(
                    sessionId != null ? sessionId.toString() : null,
                    jwtKid,
                    jwtJti
            );
            log.debug("✓ Session JTI updated successfully");
        } catch (Exception e) {
            log.error("Error calling UpdateSessionJti", e);
            throw new AuthException(
                    ErrorCode.DATABASE_ERROR,
                    "Update session JTI failed: " + e.getMessage(),
                    e
            );
        }
    }

    @Override
    public FirebaseLoginProcedureResult loginIdxMobile(
            String firebaseToken,
            String userId,
            String terminal,
            String channel,
            String version,
            String deviceId,
            String userAgent,
            String ipAddress,
            Boolean mfaEnforced
    ) {
        log.info("=== LoginIDXMobile Parameters ===");
        log.info("FirebaseToken: {}", firebaseToken != null ? "***" : null);
        log.info("UserId: {}", userId);
        log.info("Channel: {}", channel);
        log.info("DeviceId: {}", deviceId);
        log.info("MfaEnforced: {}", mfaEnforced);
        log.info("==================================");

        SimpleJdbcCall jdbcCall = new SimpleJdbcCall(dataSource)
                .withSchemaName("Auth")
                .withProcedureName("LoginIDXMobile")
                .declareParameters(
                        new SqlParameter("FirebaseToken", Types.NVARCHAR),
                        new SqlParameter("UserId", Types.NVARCHAR),
                        new SqlParameter("Terminal", Types.NVARCHAR),
                        new SqlParameter("Channel", Types.NVARCHAR),
                        new SqlParameter("Version", Types.NVARCHAR),
                        new SqlParameter("DeviceId", Types.NVARCHAR),
                        new SqlParameter("UserAgent", Types.NVARCHAR),
                        new SqlParameter("IPAddress", Types.NVARCHAR),
                        new SqlParameter("MfaEnforced", Types.BIT)
                )
                .returningResultSet("#result-set-1", (rs, rowNum) -> {
                    Map<String, Object> row = new java.util.LinkedHashMap<>();
                    int columnCount = rs.getMetaData().getColumnCount();
                    for (int i = 1; i <= columnCount; i++) {
                        row.put(rs.getMetaData().getColumnName(i), rs.getObject(i));
                    }
                    return row;
                });

        Map<String, Object> spResult;

        try {
            spResult = jdbcCall.execute(
                    firebaseToken, userId, terminal, channel, version,
                    deviceId, userAgent, ipAddress, mfaEnforced
            );

            log.info("=== Firebase SP Result ===");
            spResult.forEach((key, value) -> log.info("{} = {}", key, value));
            log.info("==========================");

            Map<String, Object> actualData = extractFirstRow(spResult, "#result-set-1");

            if (actualData == null || actualData.isEmpty()) {
                throw new AuthException(
                        ErrorCode.DATABASE_ERROR,
                        "No data returned from Firebase login procedure"
                );
            }

            return mapToFirebaseLoginResult(actualData);

        } catch (AuthException e) {
            throw e;
        } catch (Exception e) {
            log.error("❌ Error calling LoginIDXMobile", e);
            throw new AuthException(
                    ErrorCode.DATABASE_ERROR,
                    "Firebase login procedure failed: " + e.getMessage(),
                    e
            );
        }
    }

    @Override
    public void updateUserLoginSuccess(
            String userId,
            String lastLoginSuccess,
            Integer serverNumber,
            String terminalId,
            UUID sessionId,
            String jwtKid,
            String jwtJti,
            String ip,
            String userAgent
    ) {
        log.debug("Calling updateUserLoginSuccess_v2 for userId: {}", userId);

        SimpleJdbcCall jdbcCall = new SimpleJdbcCall(dataSource)
                .withSchemaName("dbo")
                .withProcedureName("updateUserLoginSuccess_v2")
                .declareParameters(
                        new SqlParameter("UserID", Types.NVARCHAR),
                        new SqlParameter("LastLoginSuccess", Types.NVARCHAR),
                        new SqlParameter("ServerNumber", Types.INTEGER),
                        new SqlParameter("TerminalId", Types.NVARCHAR),
                        new SqlParameter("SessionId", Types.VARCHAR),
                        new SqlParameter("JwtKid", Types.NVARCHAR),
                        new SqlParameter("JwtJti", Types.NVARCHAR),
                        new SqlParameter("Ip", Types.NVARCHAR),
                        new SqlParameter("UserAgent", Types.NVARCHAR)
                );

        try {
            jdbcCall.execute(
                    userId, lastLoginSuccess, serverNumber, terminalId,
                    sessionId != null ? sessionId.toString() : null,
                    jwtKid, jwtJti, ip, userAgent
            );
        } catch (Exception e) {
            log.error("Error calling updateUserLoginSuccess", e);
            throw new AuthException(
                    ErrorCode.DATABASE_ERROR,
                    "Update login success failed: " + e.getMessage(),
                    e
            );
        }
    }

    @Override
    public void updateUserLoginFail(
            String userId,
            Integer maxLoginRetry,
            String lastLoginFail
    ) {
        log.debug("Calling updateUserLoginFail_v2 for userId: {}", userId);

        SimpleJdbcCall jdbcCall = new SimpleJdbcCall(dataSource)
                .withSchemaName("dbo")
                .withProcedureName("updateUserLoginFail_v2")
                .declareParameters(
                        new SqlParameter("UserID", Types.NVARCHAR),
                        new SqlParameter("MaxLoginRetry", Types.INTEGER),
                        new SqlParameter("LastLoginFail", Types.NVARCHAR)
                );

        try {
            jdbcCall.execute(userId, maxLoginRetry, lastLoginFail);
        } catch (Exception e) {
            log.error("Error calling updateUserLoginFail", e);
            throw new AuthException(
                    ErrorCode.DATABASE_ERROR,
                    "Update login fail failed: " + e.getMessage(),
                    e
            );
        }
    }

    // ========================================
    // Helper methods
    // ========================================

    @SuppressWarnings("unchecked")
    private Map<String, Object> extractFirstRow(Map<String, Object> spResult, String resultSetKey) {
        Object resultSetObj = spResult.get(resultSetKey);

        if (resultSetObj == null) {
            log.warn("No result set found with key: {}", resultSetKey);
            return null;
        }

        if (!(resultSetObj instanceof List)) {
            log.warn("Result set is not a List: {}", resultSetObj.getClass());
            return null;
        }

        List<Map<String, Object>> resultList = (List<Map<String, Object>>) resultSetObj;

        if (resultList.isEmpty()) {
            log.warn("Result set is empty");
            return null;
        }

        return resultList.get(0);
    }

    private LoginProcedureResult mapToLoginResult(Map<String, Object> result) {
        Boolean isLoginSuccess = getBooleanFlexible(result, "IsLoginSuccess", "IsLoginSucces", "isLoginSuccess");
        String loginMessage = getStringFlexible(result, "LoginMessage", "loginMessage");
        Integer errCode = getIntegerFlexible(result, "ErrCode", "errCode");

        log.debug("Mapping - IsLoginSuccess: {}, LoginMessage: {}, ErrCode: {}",
                isLoginSuccess, loginMessage, errCode);

        return LoginProcedureResult.builder()
                .isLoginSuccess(isLoginSuccess)
                .loginMessage(loginMessage)
                .errCode(errCode)
                .dbVersion(getStringFlexible(result, "DBVersion", "dbVersion"))
                .channel(getStringFlexible(result, "Channel", "channel"))
                .sessionId(getUUIDFlexible(result, "SessionId", "sessionId"))
                .kid(getStringFlexible(result, "Kid", "kid"))
                .mfaRequired(getBooleanFlexible(result, "MfaRequired", "mfaRequired"))
                .myToken(getStringFlexible(result, "MyToken", "myToken"))
                .build();
    }

    private FirebaseLoginProcedureResult mapToFirebaseLoginResult(Map<String, Object> result) {
        return FirebaseLoginProcedureResult.builder()
                .isLoginSuccess(getBooleanFlexible(result, "IsLoginSuccess", "isLoginSuccess"))
                .loginMessage(getStringFlexible(result, "LoginMessage", "loginMessage"))
                .errCode(getIntegerFlexible(result, "ErrCode", "errCode"))
                .sessionId(getUUIDFlexible(result, "SessionId", "sessionId"))
                .kid(getStringFlexible(result, "Kid", "kid"))
                .mfaRequired(getBooleanFlexible(result, "MfaRequired", "mfaRequired"))
                .build();
    }

    private Boolean getBooleanFlexible(Map<String, Object> map, String... keys) {
        for (String key : keys) {
            Object value = map.get(key);
            if (value != null) {
                return convertToBoolean(value);
            }
        }
        log.warn("No value found for keys: {}", (Object) keys);
        return null;
    }

    private String getStringFlexible(Map<String, Object> map, String... keys) {
        for (String key : keys) {
            Object value = map.get(key);
            if (value != null) {
                String strValue = value.toString().trim();
                return strValue.isEmpty() ? null : strValue;
            }
        }
        return null;
    }

    private Integer getIntegerFlexible(Map<String, Object> map, String... keys) {
        for (String key : keys) {
            Object value = map.get(key);
            if (value != null) {
                return convertToInteger(value);
            }
        }
        return null;
    }

    private UUID getUUIDFlexible(Map<String, Object> map, String... keys) {
        for (String key : keys) {
            String value = getStringFlexible(map, key);
            if (value != null && !value.isEmpty()) {
                try {
                    return UUID.fromString(value);
                } catch (IllegalArgumentException e) {
                    log.warn("Invalid UUID format for key '{}': {}", key, value);
                }
            }
        }
        return null;
    }

    private Boolean convertToBoolean(Object value) {
        if (value instanceof Boolean) return (Boolean) value;
        if (value instanceof Number) return ((Number) value).intValue() != 0;

        String strValue = value.toString().trim().toLowerCase();
        if (strValue.isEmpty()) return null;

        if (strValue.equals("1") || strValue.equals("true") || strValue.equals("yes")) {
            return true;
        }
        if (strValue.equals("0") || strValue.equals("false") || strValue.equals("no")) {
            return false;
        }

        return Boolean.parseBoolean(strValue);
    }

    private Integer convertToInteger(Object value) {
        if (value == null) return null;

        try {
            if (value instanceof Number) return ((Number) value).intValue();
            String strValue = value.toString().trim();
            return strValue.isEmpty() ? null : Integer.parseInt(strValue);
        } catch (NumberFormatException e) {
            log.warn("Invalid integer format: {}", value);
            return null;
        }
    }
}