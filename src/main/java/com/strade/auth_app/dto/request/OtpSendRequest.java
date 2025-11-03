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
 * OTP send request
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OtpSendRequest {

    @NotNull(message = "Session ID is required")
    private UUID sessionId;

    @NotBlank(message = "Channel is required")
    @Pattern(regexp = "^(sms|email|whatsapp)$", message = "Channel must be sms, email, or whatsapp")
    private String channel;

    @NotBlank(message = "Purpose is required")
    @Size(max = 30, message = "Purpose must not exceed 30 characters")
    private String purpose = "login_2fa";

    // Optional: Override default destination (phone/email)
    @Size(max = 255, message = "Destination must not exceed 255 characters")
    private String destination;
}
