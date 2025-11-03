package com.strade.auth_app.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Session information response
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class SessionResponse {

    private UUID sessionId;
    private String userId;
    private String channel;
    private String deviceId;
    private String deviceName;
    private String ipAddress;
    private Byte status;
    private String statusText;
    private Boolean mfaRequired;
    private String mfaMethod;
    private LocalDateTime createdAt;
    private LocalDateTime lastSeenAt;
    private LocalDateTime expiresAt;

    /**
     * Get human-readable status
     */
    public String getStatusText() {
        if (status == null) {
            return "Unknown";
        }
        return switch (status) {
            case 0 -> "Pending MFA";
            case 1 -> "Active";
            case 2 -> "Revoked";
            case 3 -> "Expired";
            default -> "Unknown";
        };
    }
}
