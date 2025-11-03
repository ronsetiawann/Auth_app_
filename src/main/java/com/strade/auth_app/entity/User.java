package com.strade.auth_app.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

/**
 * User entity - untuk business validation
 * Maps to dbo.User table
 */
@Entity
@Table(name = "[User]", schema = "dbo")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {

    @Id
    @Column(name = "UserID", length = 30)
    private String userId;

    @Column(name = "Password", length = 100)
    private String password;

    @Column(name = "Enabled")
    private Boolean enable;

    @Column(name = "ExpireDate")
    private LocalDateTime expireDate;

    @Column(name = "ExpirePassword")
    private LocalDateTime expirePassword;

    @Column(name = "DisallowedTerminals", length = 500)
    private String disallowedTerminals;

    @Column(name = "AsClient")
    private Boolean asClient;

    @Column(name = "Type")
    private Integer type;

    @Column(name = "ClientID1", length = 30)
    private String clientId;

    @Column(name = "GroupPermission")
    private Boolean groupPermission;

    @Column(name = "GroupID", length = 30)
    private String groupId;

    @Column(name = "LastExitTime", length = 50)
    private String lastExitTime;

    // Business validation methods
    public boolean isEnabled() {
        return Boolean.TRUE.equals(enable);
    }

    public boolean isExpired() {
        return expireDate != null && expireDate.isBefore(LocalDateTime.now());
    }

    public boolean isPasswordExpired() {
        System.out.println("expirePassword = " + expirePassword);
        return expirePassword != null && expirePassword.isBefore(LocalDateTime.now());
    }

    public boolean isTerminalDisallowed(String terminalId) {
        return disallowedTerminals != null &&
                disallowedTerminals.contains(terminalId);
    }

    public String getRTUserId() {
        if (Boolean.TRUE.equals(groupPermission)) {
            return groupId != null ? groupId : userId;
        }
        return userId;
    }
}
