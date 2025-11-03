package com.strade.auth_app.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * MFA status response
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class MfaStatusResponse {

    private Boolean totpEnabled;
    private Byte totpStatus;
    private String totpStatusText;
    private Boolean enforced;
    private Integer backupCodesRemaining;
    private Integer backupCodesTotal;

    /**
     * Get human-readable TOTP status
     */
    public String getTotpStatusText() {
        if (totpStatus == null) {
            return "Not configured";
        }
        return switch (totpStatus) {
            case 0 -> "Inactive";
            case 1 -> "Active";
            case 2 -> "Suspended";
            default -> "Unknown";
        };
    }
}
