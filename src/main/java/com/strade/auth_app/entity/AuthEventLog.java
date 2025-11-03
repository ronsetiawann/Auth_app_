package com.strade.auth_app.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Authentication event audit log
 * Maps to Auth.AuthEventLog table
 */
@Entity
@Table(name = "AuthEventLog", schema = "Auth", indexes = {
        @Index(name = "IX_AEL_User_Time", columnList = "UserId,EventTime"),
        @Index(name = "IX_AEL_Session", columnList = "SessionId"),
        @Index(name = "IX_AEL_Type_Time", columnList = "EventType,EventTime")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuthEventLog {

    @Id
    @Column(name = "EventId", nullable = false, columnDefinition = "UNIQUEIDENTIFIER")
    private UUID eventId;

    @Column(name = "EventTime", nullable = false, columnDefinition = "DATETIME2")
    private LocalDateTime eventTime;

    @Column(name = "UserId", length = 30)
    private String userId;

    @Column(name = "SessionId", columnDefinition = "UNIQUEIDENTIFIER")
    private UUID sessionId;

    @Column(name = "EventType", length = 50, nullable = false)
    private String eventType;

    @Column(name = "Reason", length = 100)
    private String reason;

    @Column(name = "Metadata", columnDefinition = "NVARCHAR(MAX)")
    private String metadata;

    @PrePersist
    protected void onCreate() {
        if (eventId == null) {
            eventId = UUID.randomUUID();
        }
        if (eventTime == null) {
            eventTime = LocalDateTime.now();
        }
    }
}
