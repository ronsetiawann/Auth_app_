package com.strade.auth_app.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * WhatsApp webhook request (from Mekari Qontak or Twilio)
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class WhatsAppWebhookRequest {

    @NotBlank(message = "From number is required")
    private String from;          // Format: "whatsapp:+6281234567890"

    @NotBlank(message = "Message body is required")
    private String body;          // Message text (contains OTP code)

    private String messageSid;    // Message ID from provider
    private String profileName;   // Sender's name
    private String accountSid;    // Account SID

    /**
     * Extract phone number without whatsapp: prefix
     */
    public String getPhoneNumber() {
        if (from == null) {
            return null;
        }
        return from.replace("whatsapp:", "");
    }
}