package com.strade.auth_app.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

/**
 * User TOTP (Time-based OTP) configuration
 * Maps to Auth.UserMfa table
 */
@Entity
@Table(name = "UserMfa", schema = "Auth")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserMfa {

    @Id
    @Column(name = "UserId", length = 30, nullable = false)
    private String userId;

    @Column(name = "TotpSecretEnc", columnDefinition = "VARBINARY(MAX)")
    private byte[] totpSecretEnc;

    @Column(name = "TotpEnabled", nullable = false)
    private Boolean totpEnabled = false;

    /**
     * TOTP Status:
     * 0 = Inactive
     * 1 = Active
     * 2 = Suspended
     */
    @Column(name = "TotpStatus", nullable = false)
    private Byte totpStatus = 0;

    @Column(name = "TotpDigits", nullable = false)
    private Byte totpDigits = 6;

    @Column(name = "TotpPeriodSeconds", nullable = false)
    private Short totpPeriodSeconds = 30;

    @Column(name = "TotpAlgorithm", length = 10, nullable = false)
    private String totpAlgorithm = "SHA1";

    @Column(name = "LastUsedTimeStep")
    private Long lastUsedTimeStep;

    @Column(name = "Enforced", nullable = false)
    private Boolean enforced = false;

    @Column(name = "CreatedAt", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "ActivatedAt")
    private LocalDateTime activatedAt;

    @Column(name = "DeactivatedAt")
    private LocalDateTime deactivatedAt;

    @Column(name = "ActivationChannel", length = 20)
    private String activationChannel;

    @Column(name = "ActivationMethod", length = 20)
    private String activationMethod;

    @PrePersist
    protected void onCreate() {
        if (createdAt == null) {
            createdAt = LocalDateTime.now();
        }
    }

    // Helper methods
    public boolean isTotpActive() {
        return totpStatus == 1 && totpEnabled;
    }
}