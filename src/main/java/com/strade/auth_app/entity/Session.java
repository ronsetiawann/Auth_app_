package com.strade.auth_app.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * User session entity
 * Maps to Auth.Session table
 */
@Entity
@Table(name = "Session", schema = "Auth", indexes = {
        @Index(name = "IX_Session_User_Status_Channel", columnList = "UserId,Status,Channel,SessionId,CreatedAt"),
        @Index(name = "IX_Session_DeviceId", columnList = "DeviceId,Status"),
        @Index(name = "IX_Session_User_Status", columnList = "UserId,Status,Channel,CreatedAt")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Session {

    @Id
    @Column(name = "SessionId", nullable = false, columnDefinition = "UNIQUEIDENTIFIER")
    private UUID sessionId;

    @Column(name = "UserId", length = 30, nullable = false)
    private String userId;

    @Column(name = "Channel", length = 50, nullable = false)
    private String channel;

    @Column(name = "AppCode", length = 50)
    private String appCode;

    @Column(name = "AppVersion", length = 50)
    private String appVersion;

    @Column(name = "ServerNo")
    private Integer serverNo;

    @Column(name = "TerminalId", length = 50)
    private String terminalId;

    @Column(name = "IPAddress", length = 45)
    private String ipAddress;

    @Column(name = "DeviceId", length = 100)
    private String deviceId;

    @Column(name = "UserAgent", length = 200)
    private String userAgent;

    @Column(name = "JwtKid", length = 64)
    private String jwtKid;

    @Column(name = "TokenFamilyId", nullable = false, columnDefinition = "UNIQUEIDENTIFIER")
    private UUID tokenFamilyId;

    /**
     * Session status:
     * 0 = Pending MFA
     * 1 = Active
     * 2 = Revoked
     * 3 = Expired
     */
    @Column(name = "Status", nullable = false)
    private Byte status = 0;

    @Column(name = "MfaRequired", nullable = false)
    private Boolean mfaRequired = false;

    @Column(name = "MfaMethod", length = 20)
    private String mfaMethod;

    @Column(name = "MfaVerifiedAt")
    private LocalDateTime mfaVerifiedAt;

    @Column(name = "CreatedAt", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "LastSeenAt")
    private LocalDateTime lastSeenAt;

    @Column(name = "ExpiresAt")
    private LocalDateTime expiresAt;

    @Column(name = "RevokedAt")
    private LocalDateTime revokedAt;

    @Column(name = "RevokedReason", length = 100)
    private String revokedReason;

    @Column(name = "FirebaseToken", length = 255)
    private String firebaseToken;

    @Column(name = "FirebaseVerified", nullable = false)
    private Boolean firebaseVerified = false;

    @PrePersist
    protected void onCreate() {
        if (sessionId == null) {
            sessionId = UUID.randomUUID();
        }
        if (tokenFamilyId == null) {
            tokenFamilyId = UUID.randomUUID();
        }
        if (createdAt == null) {
            createdAt = LocalDateTime.now();
        }
    }

    // Helper methods
    public boolean isPending() {
        return status == 0;
    }

    public boolean isActive() {
        return status == 1;
    }

    public boolean isRevoked() {
        return status == 2;
    }

    public boolean isExpired() {
        return status == 3;
    }
}
