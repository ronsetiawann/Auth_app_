package com.strade.auth_app.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * TOTP setup response
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class TotpSetupResponse {

    private String secret;              // Base32-encoded secret
    private String qrCodeUri;           // otpauth:// URI for QR code
    private List<String> backupCodes;   // One-time backup codes
    private String issuer;
    private Integer digits;
    private Integer period;
    private String algorithm;
}
