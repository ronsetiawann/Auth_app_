package com.strade.auth_app.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Backup codes for TOTP recovery
 * Maps to Auth.UserMfaBackupCode table
 */
@Entity
@Table(name = "UserMfaBackupCode", schema = "Auth", indexes = {
        @Index(name = "IX_MfaBackup_User", columnList = "UserId"),
        @Index(name = "IX_MfaBackup_Used", columnList = "UserId,UsedAt")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserMfaBackupCode {

    @Id
    @Column(name = "Id", nullable = false, columnDefinition = "UNIQUEIDENTIFIER")
    private UUID id;

    @Column(name = "UserId", length = 30, nullable = false)
    private String userId;

    @Column(name = "CodeHash", length = 32, nullable = false)
    private byte[] codeHash;

    @Column(name = "UsedAt")
    private LocalDateTime usedAt;

    @Column(name = "CreatedAt", nullable = false)
    private LocalDateTime createdAt;

    @PrePersist
    protected void onCreate() {
        if (id == null) {
            id = UUID.randomUUID();
        }
        if (createdAt == null) {
            createdAt = LocalDateTime.now();
        }
    }

    // Helper methods
    public boolean isUsed() {
        return usedAt != null;
    }

    public boolean isAvailable() {
        return usedAt == null;
    }
}
