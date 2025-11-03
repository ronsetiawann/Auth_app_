package com.strade.auth_app.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Untrust device request
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UntrustDeviceRequest {

    @NotBlank(message = "Device ID is required")
    @Size(max = 100, message = "Device ID must not exceed 100 characters")
    private String deviceId;

    @Size(max = 50, message = "Channel must not exceed 50 characters")
    private String channel;
}
