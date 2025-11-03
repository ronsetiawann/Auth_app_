package com.strade.auth_app.repository.procedure.impl;

import com.strade.auth_app.exception.AuthException;
import com.strade.auth_app.exception.ErrorCode;
import com.strade.auth_app.repository.procedure.MfaProcedureRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.SqlOutParameter;
import org.springframework.jdbc.core.SqlParameter;
import org.springframework.jdbc.core.simple.SimpleJdbcCall;
import org.springframework.stereotype.Repository;

import javax.sql.DataSource;
import java.sql.Timestamp;
import java.sql.Types;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Slf4j
@Repository
@RequiredArgsConstructor
public class MfaProcedureRepositoryImpl implements MfaProcedureRepository {

    private final DataSource dataSource;

    @Override
    public UUID createOtpChallenge(
            String userId,
            UUID sessionId,
            String purpose,
            String channel,
            String destination,
            byte[] codeHash,
            Integer ttlSeconds,
            String reference
    ) {
        log.debug("Calling CreateOtpChallenge for userId: {}, purpose: {}", userId, purpose);

        try {
            SimpleJdbcCall jdbcCall = new SimpleJdbcCall(dataSource)
                    .withSchemaName("Auth")
                    .withProcedureName("CreateOtpChallenge")
                    .declareParameters(
                            new SqlParameter("UserId", Types.NVARCHAR),
                            new SqlParameter("SessionId", Types.VARCHAR),
                            new SqlParameter("Purpose", Types.NVARCHAR),
                            new SqlParameter("Channel", Types.NVARCHAR),
                            new SqlParameter("Destination", Types.NVARCHAR),
                            new SqlParameter("CodeHash", Types.VARBINARY),
                            new SqlParameter("TtlSeconds", Types.INTEGER),
                            new SqlOutParameter("ChallengeId", Types.VARCHAR)
                    );

            Map<String, Object> result = jdbcCall.execute(
                    userId,
                    sessionId != null ? sessionId.toString() : null,
                    purpose,
                    channel,
                    destination,
                    codeHash,
                    ttlSeconds
            );

            String challengeIdStr = (String) result.get("ChallengeId");

            if (challengeIdStr != null && !challengeIdStr.isEmpty()) {
                log.info("OTP challenge created: {}", challengeIdStr);
                return UUID.fromString(challengeIdStr);
            }

            log.warn("CreateOtpChallenge returned null");
            return null;

        } catch (Exception e) {
            log.error("Error calling CreateOtpChallenge: {}", e.getMessage(), e);
            throw new AuthException(ErrorCode.DATABASE_ERROR, "Create OTP challenge failed", e);
        }
    }

    @Override
    public void verifyOtpForLogin(
            String userId,
            UUID sessionId,
            UUID challengeId,
            byte[] codeHash,
            Boolean trustThisDevice,
            Integer trustTtlDays,
            String deviceType,
            String deviceName,
            Integer maxTrustedDevices,
            Boolean sendEmailNotification
    ) {
        log.debug("Calling VerifyOtpForLogin for userId: {}, challengeId: {}", userId, challengeId);

        try {
            SimpleJdbcCall jdbcCall = new SimpleJdbcCall(dataSource)
                    .withSchemaName("Auth")
                    .withProcedureName("VerifyOtpForLogin")
                    .declareParameters(
                            new SqlParameter("UserId", Types.NVARCHAR),
                            new SqlParameter("SessionId", Types.VARCHAR),
                            new SqlParameter("ChallengeId", Types.VARCHAR),
                            new SqlParameter("CodeHash", Types.VARBINARY),
                            new SqlParameter("TrustThisDevice", Types.BIT),
                            new SqlParameter("TrustTtlDays", Types.INTEGER),
                            new SqlParameter("DeviceType", Types.NVARCHAR),
                            new SqlParameter("DeviceName", Types.NVARCHAR),
                            new SqlParameter("MaxTrustedDevices", Types.INTEGER),
                            new SqlParameter("SendEmailNotification", Types.BIT)
                    );

            jdbcCall.execute(
                    userId,
                    sessionId.toString(),
                    challengeId.toString(),
                    codeHash,
                    trustThisDevice,
                    trustTtlDays,
                    deviceType,
                    deviceName,
                    maxTrustedDevices,
                    sendEmailNotification
            );

        } catch (Exception e) {
            log.error("Error calling VerifyOtpForLogin: {}", e.getMessage(), e);

            // Parse specific OTP errors
            String message = e.getMessage();
            if (message != null) {
                if (message.contains("OTP_NOT_FOUND")) {
                    throw new AuthException(ErrorCode.OTP_NOT_FOUND, "OTP challenge not found", e);
                } else if (message.contains("OTP_EXPIRED")) {
                    throw new AuthException(ErrorCode.OTP_EXPIRED, "OTP has expired", e);
                } else if (message.contains("OTP_INVALID")) {
                    throw new AuthException(ErrorCode.OTP_INVALID, "Invalid OTP code", e);
                } else if (message.contains("OTP_MAX_ATTEMPTS")) {
                    throw new AuthException(ErrorCode.OTP_MAX_ATTEMPTS, "Maximum OTP attempts reached", e);
                }
            }

            throw new AuthException(ErrorCode.DATABASE_ERROR, "Verify OTP failed", e);
        }
    }

    @Override
    public void verifyTotpForLogin(
            String userId,
            UUID sessionId,
            Boolean totpOk,
            Boolean trustThisDevice,
            Integer trustTtlDays,
            String deviceType,
            String deviceName,
            Integer maxTrustedDevices,
            Boolean sendEmailNotification
    ) {
        log.debug("Calling VerifyTotpForLogin for userId: {}", userId);

        try {
            SimpleJdbcCall jdbcCall = new SimpleJdbcCall(dataSource)
                    .withSchemaName("Auth")
                    .withProcedureName("VerifyTotpForLogin")
                    .declareParameters(
                            new SqlParameter("UserId", Types.NVARCHAR),
                            new SqlParameter("SessionId", Types.VARCHAR),
                            new SqlParameter("TotpOk", Types.BIT),
                            new SqlParameter("TrustThisDevice", Types.BIT),
                            new SqlParameter("TrustTtlDays", Types.INTEGER),
                            new SqlParameter("DeviceType", Types.NVARCHAR),
                            new SqlParameter("DeviceName", Types.NVARCHAR),
                            new SqlParameter("MaxTrustedDevices", Types.INTEGER),
                            new SqlParameter("SendEmailNotification", Types.BIT)
                    );

            jdbcCall.execute(
                    userId,
                    sessionId.toString(),
                    totpOk,
                    trustThisDevice,
                    trustTtlDays,
                    deviceType,
                    deviceName,
                    maxTrustedDevices,
                    sendEmailNotification
            );

        } catch (Exception e) {
            log.error("Error calling VerifyTotpForLogin: {}", e.getMessage(), e);

            if (e.getMessage() != null && e.getMessage().contains("TOTP_INVALID")) {
                throw new AuthException(ErrorCode.TOTP_INVALID, "Invalid TOTP code", e);
            }

            throw new AuthException(ErrorCode.DATABASE_ERROR, "Verify TOTP failed", e);
        }
    }

    @Override
    public void processIncomingWhatsAppOtp(
            String fromNumber,
            String messageText,
            String messageId
    ) {
        log.debug("Calling ProcessIncomingWhatsAppOtp from: {}", fromNumber);

        try {
            SimpleJdbcCall jdbcCall = new SimpleJdbcCall(dataSource)
                    .withSchemaName("Auth")
                    .withProcedureName("ProcessIncomingWhatsAppOtp")
                    .declareParameters(
                            new SqlParameter("FromNumber", Types.NVARCHAR),
                            new SqlParameter("MessageText", Types.NVARCHAR),
                            new SqlParameter("MessageId", Types.NVARCHAR)
                    );

            jdbcCall.execute(fromNumber, messageText, messageId);

        } catch (Exception e) {
            log.error("Error calling ProcessIncomingWhatsAppOtp: {}", e.getMessage(), e);
            // Don't throw - this is a webhook callback, log error and continue
            log.warn("WhatsApp OTP processing failed, but continuing to prevent webhook retry");
        }
    }

    /**
     * Verify OTP challenge code
     *
     * @param challengeId Challenge ID
     * @param codeHash Hashed OTP code
     * @return true if valid, false otherwise
     */
    @Override
    public boolean verifyOtpChallenge(UUID challengeId, byte[] codeHash) {
        log.debug("Calling VerifyOtpChallenge for challengeId: {}", challengeId);

        try {
            SimpleJdbcCall jdbcCall = new SimpleJdbcCall(dataSource)
                    .withSchemaName("Auth")
                    .withProcedureName("VerifyOtpChallenge")
                    .declareParameters(
                            new SqlParameter("ChallengeId", Types.VARCHAR),
                            new SqlParameter("CodeHash", Types.VARBINARY)
                    )
                    .returningResultSet("resultSet", (rs, rowNum) -> {
                        Map<String, Object> result = new HashMap<>();
                        result.put("IsValid", rs.getBoolean("IsValid"));
                        result.put("SessionId", rs.getString("SessionId"));
                        return result;
                    });

            Map<String, Object> result = jdbcCall.execute(
                    challengeId.toString(),
                    codeHash
            );

            // Extract result from result set
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> resultList =
                    (List<Map<String, Object>>) result.get("resultSet");

            if (resultList != null && !resultList.isEmpty()) {
                Boolean isValid = (Boolean) resultList.get(0).get("IsValid");

                if (Boolean.TRUE.equals(isValid)) {
                    log.info("OTP challenge verified successfully: challengeId={}", challengeId);
                } else {
                    log.warn("OTP challenge verification failed: challengeId={}", challengeId);
                }

                return Boolean.TRUE.equals(isValid);
            }

            log.warn("OTP challenge not found: challengeId={}", challengeId);
            return false;

        } catch (Exception e) {
            log.error("Error calling VerifyOtpChallenge: {}", e.getMessage(), e);

            if (e.getMessage() != null && e.getMessage().contains("OTP_INVALID")) {
                throw new AuthException(ErrorCode.OTP_INVALID, "Invalid or expired OTP code", e);
            }

            throw new AuthException(ErrorCode.DATABASE_ERROR, "Verify OTP challenge failed", e);
        }
    }

    @Override
    public UUID completeMfaLogin(
            String userId,
            UUID sessionId,
            String jwtKid,
            String jwtJti,
            byte[] refreshTokenHash,
            LocalDateTime refreshTokenExp,
            String ipAddress,
            String userAgent,
            String terminalId,
            Integer serverNo
    ) {
        log.debug("Calling CompleteMfaLogin for userId: {}, sessionId: {}", userId, sessionId);

        try {
            SimpleJdbcCall jdbcCall = new SimpleJdbcCall(dataSource)
                    .withSchemaName("Auth")
                    .withProcedureName("CompleteMfaLogin")
                    .declareParameters(
                            new SqlParameter("UserId", Types.NVARCHAR),
                            new SqlParameter("SessionId", Types.VARCHAR),
                            new SqlParameter("JwtKid", Types.NVARCHAR),
                            new SqlParameter("JwtJti", Types.NVARCHAR),
                            new SqlParameter("RefreshTokenHash", Types.VARBINARY),
                            new SqlParameter("RefreshTokenExp", Types.TIMESTAMP),
                            new SqlParameter("IPAddress", Types.NVARCHAR),
                            new SqlParameter("UserAgent", Types.NVARCHAR),
                            new SqlParameter("TerminalId", Types.NVARCHAR),
                            new SqlParameter("ServerNo", Types.INTEGER),
                            new SqlOutParameter("RefreshId", Types.VARCHAR)
                    );

            Map<String, Object> result = jdbcCall.execute(
                    userId,
                    sessionId.toString(),
                    jwtKid,
                    jwtJti,
                    refreshTokenHash,
                    Timestamp.valueOf(refreshTokenExp),
                    ipAddress,
                    userAgent,
                    terminalId,
                    serverNo
            );

            String refreshIdStr = (String) result.get("RefreshId");

            log.info("MFA login completed: userId={}, sessionId={}, refreshId={}",
                    userId, sessionId, refreshIdStr);

            return refreshIdStr != null ? UUID.fromString(refreshIdStr) : null;

        } catch (Exception e) {
            log.error("Error calling CompleteMfaLogin: {}", e.getMessage(), e);
            throw new AuthException(ErrorCode.DATABASE_ERROR, "Complete MFA login failed", e);
        }
    }
}