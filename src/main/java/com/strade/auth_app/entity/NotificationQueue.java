package com.strade.auth_app.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Notification queue for async email/SMS/WhatsApp delivery
 * Maps to Auth.NotificationQueue table
 */
@Entity
@Table(name = "NotificationQueue", schema = "Auth", indexes = {
        @Index(name = "IX_NotificationQueue_Status", columnList = "Status,CreatedAt"),
        @Index(name = "IX_NotificationQueue_User", columnList = "UserId,Type"),
        @Index(name = "IX_Notif_Status_Created", columnList = "Status,CreatedAt,UserId,Type")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class NotificationQueue {

    @Id
    @Column(name = "NotificationId", nullable = false, columnDefinition = "UNIQUEIDENTIFIER")
    private UUID notificationId;

    @Column(name = "UserId", length = 30, nullable = false)
    private String userId;

    @Column(name = "Type", length = 50, nullable = false)
    private String type;

    @Column(name = "Channel", length = 20, nullable = false)
    private String channel;

    @Column(name = "Destination", length = 255, nullable = false)
    private String destination;

    @Column(name = "Subject", length = 200)
    private String subject;

    @Column(name = "Body", columnDefinition = "NVARCHAR(MAX)")
    private String body;

    @Column(name = "TemplateData", columnDefinition = "NVARCHAR(MAX)")
    private String templateData;

    /**
     * Status:
     * 0 = Pending
     * 1 = Sent
     * 2 = Failed
     */
    @Column(name = "Status", nullable = false)
    private Byte status = 0;

    @Column(name = "CreatedAt", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "SentAt")
    private LocalDateTime sentAt;

    @Column(name = "ErrorMessage", length = 500)
    private String errorMessage;

    @Column(name = "RetryCount", nullable = false)
    private Byte retryCount = 0;

    @PrePersist
    protected void onCreate() {
        if (notificationId == null) {
            notificationId = UUID.randomUUID();
        }
        if (createdAt == null) {
            createdAt = LocalDateTime.now();
        }
    }

    // Helper methods
    public boolean isPending() {
        return status == 0;
    }

    public boolean isSent() {
        return status == 1;
    }

    public boolean isFailed() {
        return status == 2;
    }

    public boolean canRetry() {
        return retryCount < 3;
    }
}
