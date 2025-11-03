package com.strade.auth_app.dto.request;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

/**
 * Trust device request
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TrustDeviceRequest {

    @NotNull(message = "Session ID is required")
    private UUID sessionId;

    @NotNull(message = "Challenge ID is required")
    private UUID challengeId;

    @Pattern(regexp = "^\\d{6}$", message = "OTP code must be 6 digits")
    private String otpCode;

    @Size(max = 100, message = "Device ID must not exceed 100 characters")
    private String deviceId;

    @Size(max = 20, message = "Device type must not exceed 20 characters")
    private String deviceType;

    @Size(max = 100, message = "Device name must not exceed 100 characters")
    private String deviceName;

    @Builder.Default
    private Integer ttlDays = 90;
}
