package com.strade.auth_app.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

/**
 * TOTP activation request
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TotpActivateRequest {

    @NotBlank(message = "Code is required")
    @Pattern(regexp = "^\\d{6}$", message = "TOTP code must be 6 digits")
    private String code;
    // For no auth mode
    private String userId;
    private UUID sessionId;
    // Add these fields for trust device (during login flow)
    private Boolean trustThisDevice;
    private String deviceType;
    private String deviceName;
}
