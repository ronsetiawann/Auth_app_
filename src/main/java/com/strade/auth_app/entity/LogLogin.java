package com.strade.auth_app.entity;

import jakarta.persistence.*;
import lombok.*;

/**
 * Log Login entity - untuk track login retry
 * Maps to dbo.Log_Login table
 */
@Entity
@Table(name = "Log_Login", schema = "dbo")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class LogLogin {

    @Id
    @Column(name = "UserID", length = 30)
    private String userId;

    @Column(name = "LoginRetry")
    private Integer loginRetry;

    @Column(name = "LastLoginSuccessTime", length = 50)
    private String lastLoginSuccessTime;

    @Column(name = "LastLoginFailTime", length = 50)
    private String lastLoginFailTime;

    // Business methods
    public boolean isLocked() {
        return loginRetry != null && loginRetry <= 0;
    }

    public void incrementFailure() {
        if (loginRetry == null) {
            loginRetry = 5;
        }
        if (loginRetry > 0) {
            loginRetry--;
        }
    }

    public void resetRetry() {
        loginRetry = 5;
    }
}
