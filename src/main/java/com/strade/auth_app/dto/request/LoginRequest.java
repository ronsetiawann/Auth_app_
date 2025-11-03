package com.strade.auth_app.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Standard login request (RT/Web)
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LoginRequest {

    @NotBlank(message = "User ID is required")
    @Size(max = 30, message = "User ID must not exceed 30 characters")
    private String userId;

    @NotBlank(message = "Password is required")
    private String password;

    @NotBlank(message = "Channel is required")
    @Size(max = 50, message = "Channel must not exceed 50 characters")
    private String channel;

    @Size(max = 50, message = "App version must not exceed 50 characters")
    private String appVersion;

    private Integer serverNo;

    @Size(max = 50, message = "Terminal ID must not exceed 50 characters")
    private String terminalId;

    @Size(max = 50, message = "App code must not exceed 50 characters")
    private String appCode;

    // Optional: For explicit device fingerprint
    @Size(max = 100, message = "Device ID must not exceed 100 characters")
    private String deviceId;

    @Size(max = 200, message = "User agent must not exceed 200 characters")
    private String userAgent;
}
