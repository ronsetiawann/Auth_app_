package com.strade.auth_app.controller;

import com.strade.auth_app.dto.request.UntrustDeviceRequest;
import com.strade.auth_app.dto.response.ApiResponse;
import com.strade.auth_app.dto.response.TrustedDeviceListResponse;
import com.strade.auth_app.security.SecurityContextUtil;
import com.strade.auth_app.service.DeviceService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * Trusted Device Management REST API Controller
 */
@RestController
@RequestMapping("/api/v1/devices")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Devices", description = "Trusted Device Management APIs")
public class DeviceController {

    private final DeviceService deviceService;

    /**
     * List trusted devices
     * GET /api/v1/devices
     */
    @GetMapping
    @Operation(summary = "List trusted devices", description = "List all trusted devices for current user")
    public ResponseEntity<ApiResponse<TrustedDeviceListResponse>> listTrustedDevices() {
        String userId = SecurityContextUtil.requireAuthentication().getUserId();

        log.debug("List trusted devices: userId={}", userId);

        TrustedDeviceListResponse response = deviceService.listTrustedDevices(userId);

        return ResponseEntity.ok(ApiResponse.success(response));
    }

    /**
     * Untrust a device
     * DELETE /api/v1/devices
     */
    @DeleteMapping
    @Operation(summary = "Untrust device", description = "Remove device from trusted list")
    public ResponseEntity<ApiResponse<Void>> untrustDevice(
            @Valid @RequestBody UntrustDeviceRequest request
    ) {
        String userId = SecurityContextUtil.requireAuthentication().getUserId();

        log.info("Untrust device: userId={}, deviceId={}", userId, request.getDeviceId());

        deviceService.untrustDevice(userId, request.getDeviceId(), request.getChannel());

        return ResponseEntity.ok(ApiResponse.success(null));
    }

    /**
     * Untrust all devices
     * DELETE /api/v1/devices/all
     */
    @DeleteMapping("/all")
    @Operation(summary = "Untrust all devices", description = "Remove all trusted devices")
    public ResponseEntity<ApiResponse<Void>> untrustAllDevices() {
        String userId = SecurityContextUtil.requireAuthentication().getUserId();

        log.info("Untrust all devices: userId={}", userId);

        deviceService.untrustAllDevices(userId);

        return ResponseEntity.ok(ApiResponse.success(null));
    }
}
