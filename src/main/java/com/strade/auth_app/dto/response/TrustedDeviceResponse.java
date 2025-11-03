package com.strade.auth_app.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Trusted device response
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class TrustedDeviceResponse {

    private UUID trustedDeviceId;
    private String deviceId;
    private String deviceName;
    private String deviceType;
    private String channel;
    private LocalDateTime trustedSetAt;
    private LocalDateTime trustedUntil;
    private Boolean isCurrentlyValid;
    private String trustedByMfaMethod;
}
