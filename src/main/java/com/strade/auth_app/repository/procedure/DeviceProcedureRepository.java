package com.strade.auth_app.repository.procedure;

import com.strade.auth_app.repository.procedure.dto.TrustedDeviceInfo;

import java.util.List;

/**
 * Repository for trusted device stored procedures
 */
public interface DeviceProcedureRepository {
    /**
     * Set device as trusted
     * Application-configured parameters
     */
    void setTrustedDevice(
            String userId,
            String deviceId,
            Integer trustTtlDays,
            String mfaMethod,
            String channel,
            String deviceType,
            String deviceName,
            Integer maxTrustedDevices,
            Boolean sendEmailNotification
    );

    /**
     * Untrust a device
     */
    void untrustDevice(
            String userId,
            String deviceId,
            String channel,
            Boolean sendEmailNotification
    );

    /**
     * Untrust all devices
     */
    void untrustAllDevices(
            String userId,
            Boolean sendEmailNotification
    );

    /**
     * List trusted devices
     */
    List<TrustedDeviceInfo> listTrustedDevices(String userId);
}