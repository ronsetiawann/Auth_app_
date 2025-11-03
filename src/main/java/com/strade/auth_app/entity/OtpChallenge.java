package com.strade.auth_app.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * OTP challenge for multi-factor authentication
 * Maps to Auth.OtpChallenge table
 */
@Entity
@Table(name = "OtpChallenge", schema = "Auth", indexes = {
        @Index(name = "IX_Otp_User_Status", columnList = "UserId,Status,Purpose"),
        @Index(name = "IX_Otp_Session", columnList = "SessionId,Status"),
        @Index(name = "IX_Otp_Expires", columnList = "ExpiresAt,Status"),
        @Index(name = "IX_Otp_Destination", columnList = "Destination,Channel,Status,UserId,CodeHash,ExpiresAt")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class OtpChallenge {

    @Id
    @Column(name = "ChallengeId", nullable = false, columnDefinition = "UNIQUEIDENTIFIER")
    private UUID challengeId;

    @Column(name = "UserId", length = 30, nullable = false)
    private String userId;

    @Column(name = "Purpose", length = 30, nullable = false)
    private String purpose;

    @Column(name = "Channel", length = 20, nullable = false)
    private String channel;

    @Column(name = "Destination", length = 255, nullable = false)
    private String destination;

    @Column(name = "CodeHash", length = 32, nullable = false)
    private byte[] codeHash;

    @Column(name = "ExpiresAt", nullable = false)
    private LocalDateTime expiresAt;

    @Column(name = "AttemptCount", nullable = false)
    private Byte attempts = 0;

    @Column(name = "MaxAttempts", nullable = false)
    private Byte maxAttempts = 5;

    /**
     * Status:
     * 0 = Pending
     * 1 = Used
     * 2 = Expired
     * 3 = MaxAttempts
     */
    @Column(name = "Status", nullable = false)
    private Byte status = 0;

    @Column(name = "UsedAt")
    private LocalDateTime usedAt;

    @Column(name = "SessionId", columnDefinition = "UNIQUEIDENTIFIER")
    private UUID sessionId;

    @Column(name = "CreatedAt", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "CreatedFromIp", length = 45)
    private String createdFromIp;

    @Column(name = "UserAgent", length = 200)
    private String userAgent;

    @Column(name = "ProviderMsgId", length = 100)
    private String providerMsgId;

    @Column(name = "IsIncomingMessage", nullable = false)
    private Boolean isIncomingMessage = false;

    @Column(name = "Reference")
    private String reference;

    @PrePersist
    protected void onCreate() {
        if (challengeId == null) {
            challengeId = UUID.randomUUID();
        }
        if (createdAt == null) {
            createdAt = LocalDateTime.now();
        }
    }

    // Helper methods
    public boolean isPending() {
        return status == 0;
    }

    public boolean isUsed() {
        return status == 1;
    }

    public boolean isExpired() {
        return status == 2 || expiresAt.isBefore(LocalDateTime.now());
    }

    public boolean hasReachedMaxAttempts() {
        return attempts >= maxAttempts;
    }
}
