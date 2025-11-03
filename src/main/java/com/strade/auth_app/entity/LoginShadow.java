package com.strade.auth_app.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Shadow table for quick JWT claims lookup
 * Maps to Auth.LoginShadow table
 */
@Entity
@Table(name = "LoginShadow", schema = "Auth")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class LoginShadow {

    @Id
    @Column(name = "UserId", length = 30, nullable = false)
    private String userId;

    @Column(name = "SessionId", columnDefinition = "UNIQUEIDENTIFIER")
    private UUID sessionId;

    @Column(name = "LastJwtJti", length = 64)
    private String lastJwtJti;

    @Column(name = "LastJwtKid", length = 64)
    private String lastJwtKid;

    @Column(name = "LastIp", length = 45)
    private String lastIp;

    @Column(name = "LastUserAgent", length = 200)
    private String lastUserAgent;

    @Column(name = "UpdatedAt", nullable = false)
    private LocalDateTime updatedAt;

    @PrePersist
    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }
}
