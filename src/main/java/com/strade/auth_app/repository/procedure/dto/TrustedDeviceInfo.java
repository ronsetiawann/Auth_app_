package com.strade.auth_app.repository.procedure.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Trusted device information
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TrustedDeviceInfo {

    private UUID trustedDeviceId;
    private String deviceId;
    private String trustedChannel;
    private String deviceType;
    private String deviceName;
    private LocalDateTime trustedSetAt;
    private LocalDateTime trustedUntil;
    private LocalDateTime trustedRevokedAt;
    private String trustedByMfaMethod;
    private Boolean isCurrentlyValid;
}
