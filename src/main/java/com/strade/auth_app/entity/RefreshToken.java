package com.strade.auth_app.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Refresh token with rotation tracking
 * Maps to Auth.RefreshToken table
 */
@Entity
@Table(name = "RefreshToken", schema = "Auth", indexes = {
        @Index(name = "IX_RT_Session", columnList = "SessionId"),
        @Index(name = "IX_RT_Expires", columnList = "ExpiresAt,RevokedAt"),
        @Index(name = "IX_RT_Session_Status", columnList = "SessionId,RevokedAt,ExpiresAt")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RefreshToken {

    @Id
    @Column(name = "RefreshId", nullable = false, columnDefinition = "UNIQUEIDENTIFIER")
    private UUID refreshId;

    @Column(name = "SessionId", nullable = false, columnDefinition = "UNIQUEIDENTIFIER")
    private UUID sessionId;

    @Column(name = "TokenHash", nullable = false, unique = true, length = 64)
    private byte[] tokenHash;

    @Column(name = "ExpiresAt", nullable = false)
    private LocalDateTime expiresAt;

    @Column(name = "CreatedAt", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "RotatedFrom", columnDefinition = "UNIQUEIDENTIFIER")
    private UUID rotatedFrom;

    @Column(name = "RevokedAt")
    private LocalDateTime revokedAt;

    @Column(name = "RevokedReason", length = 100)
    private String revokedReason;

    @Column(name = "ReplacedBy", columnDefinition = "UNIQUEIDENTIFIER")
    private UUID replacedBy;

    @PrePersist
    protected void onCreate() {
        if (refreshId == null) {
            refreshId = UUID.randomUUID();
        }
        if (createdAt == null) {
            createdAt = LocalDateTime.now();
        }
    }

    // Helper methods
    public boolean isValid() {
        return revokedAt == null && expiresAt.isAfter(LocalDateTime.now());
    }

    public boolean isRevoked() {
        return revokedAt != null;
    }

    public boolean isExpired() {
        return expiresAt.isBefore(LocalDateTime.now());
    }
}
