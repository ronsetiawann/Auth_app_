package com.strade.auth_app.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Blacklist for revoked access tokens (JTI denylist)
 * Maps to Auth.AccessTokenDenyJti table
 */
@Entity
@Table(name = "AccessTokenDenyJti", schema = "Auth", indexes = {
        @Index(name = "IX_DenyJti_Expires", columnList = "ExpiresAt")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AccessTokenDenyJti {

    @Id
    @Column(name = "Jti", length = 64, nullable = false)
    private String jti;

    @Column(name = "SessionId", columnDefinition = "UNIQUEIDENTIFIER")
    private UUID sessionId;

    @Column(name = "UserId", length = 30)
    private String userId;

    @Column(name = "ExpiresAt", nullable = false)
    private LocalDateTime expiresAt;

    @Column(name = "RevokedAt", nullable = false)
    private LocalDateTime revokedAt;

    @Column(name = "Reason", length = 100)
    private String reason;

    @PrePersist
    protected void onCreate() {
        if (revokedAt == null) {
            revokedAt = LocalDateTime.now();
        }
    }
}
