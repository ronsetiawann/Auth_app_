package com.strade.auth_app.repository.procedure.impl;

import com.strade.auth_app.exception.AuthException;
import com.strade.auth_app.exception.ErrorCode;
import com.strade.auth_app.repository.procedure.SessionProcedureRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.SqlOutParameter;
import org.springframework.jdbc.core.SqlParameter;
import org.springframework.jdbc.core.simple.SimpleJdbcCall;
import org.springframework.stereotype.Repository;

import javax.sql.DataSource;
import java.sql.Types;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.UUID;

@Slf4j
@Repository
@RequiredArgsConstructor
public class SessionProcedureRepositoryImpl implements SessionProcedureRepository {

    private final DataSource dataSource;

    @Override
    public UUID storeRefreshOnLogin(
            UUID sessionId,
            byte[] refreshTokenHash,
            LocalDateTime refreshTokenExp
    ) {
        log.debug("Calling StoreRefreshOnLogin for sessionId: {}", sessionId);

        try {
            SimpleJdbcCall jdbcCall = new SimpleJdbcCall(dataSource)
                    .withSchemaName("Auth")
                    .withProcedureName("StoreRefreshOnLogin")
                    .declareParameters(
                            new SqlParameter("SessionId", Types.VARCHAR),
                            new SqlParameter("RefreshTokenHash", Types.VARBINARY),
                            new SqlParameter("RefreshTokenExp", Types.TIMESTAMP),
                            new SqlOutParameter("RefreshId", Types.VARCHAR)
                    );

            Map<String, Object> inParams = Map.of(
                    "SessionId", sessionId.toString(),
                    "RefreshTokenHash", refreshTokenHash,
                    "RefreshTokenExp", refreshTokenExp
            );

            Map<String, Object> result = jdbcCall.execute(inParams);

            String refreshIdStr = (String) result.get("RefreshId");
            return refreshIdStr != null ? UUID.fromString(refreshIdStr) : null;

        } catch (Exception e) {
            log.error("Error calling StoreRefreshOnLogin: {}", e.getMessage(), e);
            throw new AuthException(ErrorCode.DATABASE_ERROR, "Store refresh token failed", e);
        }
    }

    @Override
    public void rotateRefreshToken(
            UUID sessionId,
            byte[] oldRefreshHash,
            byte[] newRefreshHash,
            LocalDateTime newRefreshExp
    ) {
        log.debug("Calling RotateRefreshToken for sessionId: {}", sessionId);

        try {
            SimpleJdbcCall jdbcCall = new SimpleJdbcCall(dataSource)
                    .withSchemaName("Auth")
                    .withProcedureName("RotateRefreshToken")
                    .declareParameters(
                            new SqlParameter("SessionId", Types.VARCHAR),
                            new SqlParameter("OldRefreshHash", Types.VARBINARY),
                            new SqlParameter("NewRefreshHash", Types.VARBINARY),
                            new SqlParameter("NewRefreshExp", Types.TIMESTAMP)
                    );

            jdbcCall.execute(
                    sessionId.toString(),
                    oldRefreshHash,
                    newRefreshHash,
                    newRefreshExp
            );

        } catch (Exception e) {
            log.error("Error calling RotateRefreshToken: {}", e.getMessage(), e);

            // Check if it's a token reuse detection
            if (e.getMessage() != null && e.getMessage().contains("REFRESH_REUSE_DETECTED")) {
                throw new AuthException(ErrorCode.TOKEN_REUSE_DETECTED, "Refresh token reuse detected", e);
            }

            throw new AuthException(ErrorCode.DATABASE_ERROR, "Rotate refresh token failed", e);
        }
    }

    @Override
    public void revokeSession(UUID sessionId, String reason) {
        log.debug("Calling RevokeSession for sessionId: {}", sessionId);

        try {
            SimpleJdbcCall jdbcCall = new SimpleJdbcCall(dataSource)
                    .withSchemaName("Auth")
                    .withProcedureName("RevokeSession")
                    .declareParameters(
                            new SqlParameter("SessionId", Types.VARCHAR),
                            new SqlParameter("Reason", Types.NVARCHAR)
                    );

            jdbcCall.execute(sessionId.toString(), reason);

        } catch (Exception e) {
            log.error("Error calling RevokeSession: {}", e.getMessage(), e);
            throw new AuthException(ErrorCode.DATABASE_ERROR, "Revoke session failed", e);
        }
    }

    @Override
    public void revokeAllSessionsForUser(
            String userId,
            UUID exceptSessionId,
            String reason
    ) {
        log.debug("Calling RevokeAllSessionsForUser for userId: {}", userId);

        try {
            SimpleJdbcCall jdbcCall = new SimpleJdbcCall(dataSource)
                    .withSchemaName("Auth")
                    .withProcedureName("RevokeAllSessionsForUser")
                    .declareParameters(
                            new SqlParameter("UserId", Types.NVARCHAR),
                            new SqlParameter("ExceptSessionId", Types.VARCHAR),
                            new SqlParameter("Reason", Types.NVARCHAR)
                    );

            jdbcCall.execute(
                    userId,
                    exceptSessionId != null ? exceptSessionId.toString() : null,
                    reason
            );

        } catch (Exception e) {
            log.error("Error calling RevokeAllSessionsForUser: {}", e.getMessage(), e);
            throw new AuthException(ErrorCode.DATABASE_ERROR, "Revoke all sessions failed", e);
        }
    }

    @Override
    public boolean verifyAccessClaims(UUID sessionId, String jti, String userId) {
        log.debug("Calling VerifyAccessClaims for sessionId: {}", sessionId);

        try {
            SimpleJdbcCall jdbcCall = new SimpleJdbcCall(dataSource)
                    .withSchemaName("Auth")
                    .withProcedureName("VerifyAccessClaims")
                    .declareParameters(
                            new SqlParameter("SessionId", Types.VARCHAR),
                            new SqlParameter("Jti", Types.NVARCHAR),
                            new SqlParameter("UserId", Types.NVARCHAR)
                    );

            Map<String, Object> result = jdbcCall.execute(
                    sessionId.toString(),
                    jti,
                    userId
            );

            Object isValidObj = result.get("IsValid");
            if (isValidObj instanceof Boolean) {
                return (Boolean) isValidObj;
            } else if (isValidObj instanceof Number) {
                return ((Number) isValidObj).intValue() != 0;
            }
            return false;

        } catch (Exception e) {
            log.error("Error calling VerifyAccessClaims: {}", e.getMessage(), e);
            return false;
        }
    }
}
