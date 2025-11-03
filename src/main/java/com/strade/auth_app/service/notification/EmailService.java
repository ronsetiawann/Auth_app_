package com.strade.auth_app.service.notification;

import com.strade.auth_app.config.properties.EmailProperties;
import com.strade.auth_app.entity.NotificationQueue;
import com.strade.auth_app.exception.AuthException;
import com.strade.auth_app.exception.ErrorCode;
import com.strade.auth_app.repository.jpa.NotificationQueueRepository;
import com.strade.auth_app.util.JsonUtil;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import java.io.UnsupportedEncodingException;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Email service using SMTP
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class EmailService {

    private final JavaMailSender mailSender;
    private final EmailProperties emailProperties;
    private final NotificationQueueRepository notificationQueueRepository;

    /**
     * Send OTP via Email
     */
    public String sendOtp(String userId, String email, String name, String otpCode) {
        UUID notificationId = UUID.randomUUID();

        try {
            log.info("Sending OTP email to {} for user {}", email, userId);

            // 1. Create notification queue entry (PENDING)
            NotificationQueue notification = createNotificationQueue(
                    notificationId,
                    userId,
                    email,
                    name,
                    otpCode
            );
            notificationQueueRepository.save(notification);

            // 2. Prepare email content
            String subject = "Your OTP Code - STRADE";
            String htmlContent = buildOtpEmailHtml(name, otpCode);

            // 3. Send email
            sendEmail(email, subject, htmlContent);

            // 4. Update notification status to SENT
            notification.setStatus((byte) 1); // SENT
            notification.setSentAt(LocalDateTime.now());
            notificationQueueRepository.save(notification);

            log.info("OTP email sent successfully. NotificationId: {}", notificationId);

            return notificationId.toString();

        } catch (Exception e) {
            log.error("Failed to send OTP email for user {}", userId, e);

            // Update notification status to FAILED
            notificationQueueRepository.findById(notificationId).ifPresent(notif -> {
                notif.setStatus((byte) 2); // FAILED
                notif.setErrorMessage(e.getMessage());
                notif.setRetryCount((byte) (notif.getRetryCount() + 1));
                notificationQueueRepository.save(notif);
            });

            throw new AuthException(ErrorCode.EMAIL_SEND_FAILED, "Email send failed", e);
        }
    }

    /**
     * Send email using JavaMailSender
     */
    private void sendEmail(String to, String subject, String htmlContent) throws MessagingException, UnsupportedEncodingException {
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

        helper.setFrom(emailProperties.getFrom(), emailProperties.getFromName());
        helper.setTo(to);
        helper.setSubject(subject);
        helper.setText(htmlContent, true); // true = HTML

        mailSender.send(message);
    }

    /**
     * Create notification queue entry
     */
    private NotificationQueue createNotificationQueue(
            UUID notificationId,
            String userId,
            String email,
            String name,
            String otpCode
    ) {
        Map<String, Object> templateData = new HashMap<>();
        templateData.put("email", email);
        templateData.put("name", name);
        templateData.put("otp_code", otpCode);

        return NotificationQueue.builder()
                .notificationId(notificationId)
                .userId(userId)
                .type("OTP_LOGIN_2FA")
                .channel("email")
                .destination(email)
                .subject("Your OTP Code - STRADE")
                .body("Your OTP code is: " + otpCode)
                .templateData(JsonUtil.toJson(templateData))
                .status((byte) 0) // PENDING
                .retryCount((byte) 0)
                .createdAt(LocalDateTime.now())
                .build();
    }

    /**
     * Build OTP email HTML template
     */
    private String buildOtpEmailHtml(String name, String otpCode) {
        String template = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Your OTP Code</title>
        </head>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
            <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
                <h1 style="color: white; margin: 0;">STRADE</h1>
            </div>
            <div style="background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px;">
                <h2 style="color: #333; margin-top: 0;">Hello {NAME},</h2>
                <p>You have requested to login to your STRADE account. Please use the following One-Time Password (OTP) to complete your login:</p>
                <div style="background: white; border: 2px dashed #667eea; border-radius: 5px; padding: 20px; text-align: center; margin: 30px 0;">
                    <h1 style="color: #667eea; font-size: 36px; letter-spacing: 8px; margin: 0;">{OTP_CODE}</h1>
                </div>
                <p style="color: #666; font-size: 14px;">
                    <strong>Important:</strong>
                    <ul style="color: #666; font-size: 14px;">
                        <li>This OTP is valid for <strong>5 minutes</strong></li>
                        <li>Do not share this code with anyone</li>
                        <li>If you didn't request this OTP, please ignore this email</li>
                    </ul>
                </p>
                <hr style="border: none; border-top: 1px solid #ddd; margin: 30px 0;">
                <p style="color: #999; font-size: 12px; text-align: center;">
                    This is an automated message, please do not reply to this email.<br>
                    © 2025 STRADE. All rights reserved.
                </p>
            </div>
        </body>
        </html>
        """;

        // ✅ Replace placeholders
        return template
                .replace("{NAME}", name != null ? name : "User")
                .replace("{OTP_CODE}", otpCode);
    }
}