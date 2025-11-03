package com.strade.auth_app.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Trusted devices for MFA skip
 * Maps to Auth.TrustedDevice table
 */
@Entity
@Table(
        name = "TrustedDevice",
        schema = "Auth",
        uniqueConstraints = {
                @UniqueConstraint(
                        name = "UQ_TD_User_Device_Channel",
                        columnNames = {"UserId", "DeviceId", "TrustedChannel"}
                )
        },
        indexes = {
                @Index(name = "IX_TD_User_Active", columnList = "UserId,TrustedRevokedAt,TrustedUntil,TrustedChannel"),
                @Index(name = "IX_TD_User_Device", columnList = "UserId,DeviceId,TrustedChannel,TrustedUntil,TrustedRevokedAt")
        }
)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TrustedDevice {

    @Id
    @Column(name = "TrustedDeviceId", nullable = false, columnDefinition = "UNIQUEIDENTIFIER")
    private UUID trustedDeviceId;

    @Column(name = "UserId", length = 30, nullable = false)
    private String userId;

    @Column(name = "DeviceId", length = 100, nullable = false)
    private String deviceId;

    @Column(name = "TrustedChannel", length = 50)
    private String trustedChannel;

    @Column(name = "DeviceType", length = 20)
    private String deviceType;

    @Column(name = "DeviceName", length = 100)
    private String deviceName;

    @Column(name = "TrustedSetAt", nullable = false)
    private LocalDateTime trustedSetAt;

    @Column(name = "TrustedUntil")
    private LocalDateTime trustedUntil;

    @Column(name = "TrustedRevokedAt")
    private LocalDateTime trustedRevokedAt;

    @Column(name = "TrustedByMfaMethod", length = 20)
    private String trustedByMfaMethod;

    @PrePersist
    protected void onCreate() {
        if (trustedDeviceId == null) {
            trustedDeviceId = UUID.randomUUID();
        }
        if (trustedSetAt == null) {
            trustedSetAt = LocalDateTime.now();
        }
    }

    // Helper methods
    public boolean isActive() {
        return this.trustedRevokedAt == null &&
                (this.trustedUntil == null || LocalDateTime.now().isBefore(this.trustedUntil));
    }

    public boolean isExpired() {
        return trustedUntil != null && trustedUntil.isBefore(LocalDateTime.now());
    }

    public boolean isRevoked() {
        return trustedRevokedAt != null;
    }
}