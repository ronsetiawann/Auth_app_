package com.strade.auth_app.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

/**
 * TOTP verification request
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TotpVerifyRequest {

    @NotNull(message = "Session ID is required")
    private UUID sessionId;

    @NotBlank(message = "TOTP code is required")
    @Pattern(regexp = "^\\d{6}$", message = "TOTP code must be 6 digits")
    private String code;

    @Builder.Default
    private Boolean trustThisDevice = false;

    @Size(max = 20, message = "Device type must not exceed 20 characters")
    private String deviceType;

    @Size(max = 100, message = "Device name must not exceed 100 characters")
    private String deviceName;
}
