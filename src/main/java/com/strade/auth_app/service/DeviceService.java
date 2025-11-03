package com.strade.auth_app.service;

import com.strade.auth_app.dto.response.TrustedDeviceListResponse;
import com.strade.auth_app.dto.response.TrustedDeviceResponse;
import com.strade.auth_app.exception.AuthException;
import com.strade.auth_app.exception.ErrorCode;
import com.strade.auth_app.repository.jpa.TrustedDeviceRepository;
import com.strade.auth_app.repository.procedure.DeviceProcedureRepository;
import com.strade.auth_app.service.cache.TrustedDeviceCacheService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Trusted device management service
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class DeviceService {

    private final TrustedDeviceRepository trustedDeviceRepository;
    private final DeviceProcedureRepository deviceProcedureRepository;
    private final TrustedDeviceCacheService trustedDeviceCacheService;

    /**
     * Check if device is trusted
     */
    public boolean isTrustedDevice(String userId, String deviceId, String channel) {
        // Check cache first
        Boolean cached = trustedDeviceCacheService.getCachedTrustedDevice(userId, deviceId, channel);
        if (cached != null) {
            return cached;
        }

        // Check database
        boolean isTrusted = trustedDeviceRepository.existsActiveTrustedDevice(
                userId,
                deviceId,
                channel,
                LocalDateTime.now()
        );

        // Cache result
        trustedDeviceCacheService.cacheTrustedDevice(userId, deviceId, channel, isTrusted);

        return isTrusted;
    }

    /**
     * List trusted devices for user
     */
    public TrustedDeviceListResponse listTrustedDevices(String userId) {
        LocalDateTime now = LocalDateTime.now();
        var devices = trustedDeviceRepository.findActiveTrustedDevicesByUserId(userId, now);

        List<TrustedDeviceResponse> deviceResponses = devices.stream()
                .map(device -> TrustedDeviceResponse.builder()
                        .trustedDeviceId(device.getTrustedDeviceId())
                        .deviceId(device.getDeviceId())
                        .deviceName(device.getDeviceName())
                        .deviceType(device.getDeviceType())
                        .channel(device.getTrustedChannel())
                        .trustedSetAt(device.getTrustedSetAt())
                        .trustedUntil(device.getTrustedUntil())
                        .isCurrentlyValid(device.isActive())
                        .trustedByMfaMethod(device.getTrustedByMfaMethod())
                        .build())
                .collect(Collectors.toList());

        long totalCount = trustedDeviceRepository.countActiveTrustedDevicesByUserId(userId, now);

        return TrustedDeviceListResponse.builder()
                .devices(deviceResponses)
                .totalCount((int) totalCount)
                .activeCount(deviceResponses.size())
                .maxAllowed(3) // From config
                .availableSlots(Math.max(0, 3 - (int) totalCount))
                .build();
    }

    /**
     * Untrust a specific device
     */
    @Transactional
    public void untrustDevice(String userId, String deviceId, String channel) {
        log.info("Untrusting device: userId={}, deviceId={}", userId, deviceId);

        // Call stored procedure
        deviceProcedureRepository.untrustDevice(userId, deviceId, channel, true);

        // Invalidate cache
        trustedDeviceCacheService.invalidateTrustedDevice(userId, deviceId, channel);

        log.info("Device untrusted successfully");
    }

    /**
     * Untrust all devices for user
     */
    @Transactional
    public void untrustAllDevices(String userId) {
        log.info("Untrusting all devices for user: {}", userId);

        // Call stored procedure
        deviceProcedureRepository.untrustAllDevices(userId, true);

        // Invalidate cache
        trustedDeviceCacheService.invalidateAllUserTrustedDevices(userId);

        log.info("All devices untrusted successfully");
    }
}
