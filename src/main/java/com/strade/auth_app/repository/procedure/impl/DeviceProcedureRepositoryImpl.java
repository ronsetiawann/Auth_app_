package com.strade.auth_app.repository.procedure.impl;

import com.strade.auth_app.repository.procedure.DeviceProcedureRepository;
import com.strade.auth_app.repository.procedure.dto.TrustedDeviceInfo;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.SqlParameter;
import org.springframework.jdbc.core.simple.SimpleJdbcCall;
import org.springframework.stereotype.Repository;

import jakarta.annotation.PostConstruct;
import java.sql.Types;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Implementation of DeviceProcedureRepository using SQL Server stored procedures
 */
@Slf4j
@Repository
@RequiredArgsConstructor
public class DeviceProcedureRepositoryImpl implements DeviceProcedureRepository {

    private final JdbcTemplate jdbcTemplate;

    private SimpleJdbcCall setTrustedDeviceCall;
    private SimpleJdbcCall untrustDeviceCall;
    private SimpleJdbcCall untrustAllDevicesCall;
    private SimpleJdbcCall listTrustedDevicesCall;

    @PostConstruct
    public void init() {
        log.info("🔧 Initializing DeviceProcedureRepository stored procedure calls");

        try {
            // Initialize Auth.SetTrustedDevice
            setTrustedDeviceCall = new SimpleJdbcCall(jdbcTemplate)
                    .withSchemaName("Auth")
                    .withProcedureName("SetTrustedDevice")
                    .declareParameters(
                            new SqlParameter("UserId", Types.NVARCHAR),
                            new SqlParameter("DeviceId", Types.NVARCHAR),
                            new SqlParameter("TrustTtlDays", Types.INTEGER),
                            new SqlParameter("MfaMethod", Types.NVARCHAR),
                            new SqlParameter("Channel", Types.NVARCHAR),
                            new SqlParameter("DeviceType", Types.NVARCHAR),
                            new SqlParameter("DeviceName", Types.NVARCHAR),
                            new SqlParameter("MaxTrustedDevices", Types.INTEGER),
                            new SqlParameter("SendEmailNotification", Types.BIT)
                    );

            // Initialize Auth.UntrustDevice
            untrustDeviceCall = new SimpleJdbcCall(jdbcTemplate)
                    .withSchemaName("Auth")
                    .withProcedureName("UntrustDevice")
                    .declareParameters(
                            new SqlParameter("UserId", Types.NVARCHAR),
                            new SqlParameter("DeviceId", Types.NVARCHAR),
                            new SqlParameter("Channel", Types.NVARCHAR),
                            new SqlParameter("SendEmailNotification", Types.BIT)
                    );

            // Initialize Auth.UntrustAllDevices
            untrustAllDevicesCall = new SimpleJdbcCall(jdbcTemplate)
                    .withSchemaName("Auth")
                    .withProcedureName("UntrustAllDevices")
                    .declareParameters(
                            new SqlParameter("UserId", Types.NVARCHAR),
                            new SqlParameter("SendEmailNotification", Types.BIT)
                    );

            // Initialize Auth.ListTrustedDevices
            listTrustedDevicesCall = new SimpleJdbcCall(jdbcTemplate)
                    .withSchemaName("Auth")
                    .withProcedureName("ListTrustedDevices")
                    .returningResultSet("devices", (rs, rowNum) -> TrustedDeviceInfo.builder()
                            .trustedDeviceId(UUID.fromString(rs.getString("TrustedDeviceId")))
                            .deviceId(rs.getString("DeviceId"))
                            .trustedChannel(rs.getString("TrustedChannel"))
                            .deviceType(rs.getString("DeviceType"))
                            .deviceName(rs.getString("DeviceName"))
                            .trustedSetAt(rs.getTimestamp("TrustedSetAt") != null ?
                                    rs.getTimestamp("TrustedSetAt").toLocalDateTime() : null)
                            .trustedUntil(rs.getTimestamp("TrustedUntil") != null ?
                                    rs.getTimestamp("TrustedUntil").toLocalDateTime() : null)
                            .trustedRevokedAt(rs.getTimestamp("TrustedRevokedAt") != null ?
                                    rs.getTimestamp("TrustedRevokedAt").toLocalDateTime() : null)
                            .trustedByMfaMethod(rs.getString("TrustedByMfaMethod"))
                            .isCurrentlyValid(rs.getBoolean("IsCurrentlyValid"))
                            .build())
                    .declareParameters(
                            new SqlParameter("UserId", Types.NVARCHAR)
                    );

            log.info("✅ DeviceProcedureRepository initialized successfully");

        } catch (Exception e) {
            log.error("❌ Failed to initialize DeviceProcedureRepository", e);
            throw new RuntimeException("Failed to initialize device stored procedures", e);
        }
    }

    @Override
    public void setTrustedDevice(
            String userId,
            String deviceId,
            Integer trustTtlDays,
            String mfaMethod,
            String channel,
            String deviceType,
            String deviceName,
            Integer maxTrustedDevices,
            Boolean sendEmailNotification
    ) {
        try {
            log.debug("📱 Setting trusted device for user: {}, deviceId: {}", userId, deviceId);

            Map<String, Object> params = new HashMap<>();
            params.put("UserId", userId);
            params.put("DeviceId", deviceId);
            params.put("TrustTtlDays", trustTtlDays != null ? trustTtlDays : 90);
            params.put("MfaMethod", mfaMethod != null ? mfaMethod : "otp");
            params.put("Channel", channel);
            params.put("DeviceType", deviceType);
            params.put("DeviceName", deviceName);
            params.put("MaxTrustedDevices", maxTrustedDevices != null ? maxTrustedDevices : 3);
            params.put("SendEmailNotification", sendEmailNotification != null ? sendEmailNotification : Boolean.TRUE);

            setTrustedDeviceCall.execute(params);

            log.info("✅ Device set as trusted successfully for user: {}", userId);

        } catch (Exception e) {
            log.error("❌ Error setting trusted device for user: {}", userId, e);
            throw new RuntimeException("Failed to set trusted device: " + e.getMessage(), e);
        }
    }

    @Override
    public void untrustDevice(
            String userId,
            String deviceId,
            String channel,
            Boolean sendEmailNotification
    ) {
        try {
            log.debug("🔓 Untrusting device for user: {}, deviceId: {}", userId, deviceId);

            Map<String, Object> params = new HashMap<>();
            params.put("UserId", userId);
            params.put("DeviceId", deviceId);
            params.put("Channel", channel);
            params.put("SendEmailNotification", sendEmailNotification != null ? sendEmailNotification : Boolean.TRUE);

            untrustDeviceCall.execute(params);

            log.info("✅ Device untrusted successfully for user: {}", userId);

        } catch (Exception e) {
            log.error("❌ Error untrusting device for user: {}", userId, e);
            throw new RuntimeException("Failed to untrust device: " + e.getMessage(), e);
        }
    }

    @Override
    public void untrustAllDevices(
            String userId,
            Boolean sendEmailNotification
    ) {
        try {
            log.debug("🔓🔓 Untrusting all devices for user: {}", userId);

            Map<String, Object> params = new HashMap<>();
            params.put("UserId", userId);
            params.put("SendEmailNotification", sendEmailNotification != null ? sendEmailNotification : Boolean.TRUE);

            untrustAllDevicesCall.execute(params);

            log.info("✅ All devices untrusted successfully for user: {}", userId);

        } catch (Exception e) {
            log.error("❌ Error untrusting all devices for user: {}", userId, e);
            throw new RuntimeException("Failed to untrust all devices: " + e.getMessage(), e);
        }
    }

    @Override
    @SuppressWarnings("unchecked")
    public List<TrustedDeviceInfo> listTrustedDevices(String userId) {
        try {
            log.debug("📋 Listing trusted devices for user: {}", userId);

            Map<String, Object> params = new HashMap<>();
            params.put("UserId", userId);

            Map<String, Object> result = listTrustedDevicesCall.execute(params);
            List<TrustedDeviceInfo> devices = (List<TrustedDeviceInfo>) result.get("devices");

            log.info("✅ Found {} trusted devices for user: {}",
                    devices != null ? devices.size() : 0, userId);

            return devices != null ? devices : List.of();

        } catch (Exception e) {
            log.error("❌ Error listing trusted devices for user: {}", userId, e);
            throw new RuntimeException("Failed to list trusted devices: " + e.getMessage(), e);
        }
    }
}