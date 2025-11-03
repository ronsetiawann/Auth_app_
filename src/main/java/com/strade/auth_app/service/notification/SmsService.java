package com.strade.auth_app.service.notification;

import com.strade.auth_app.config.properties.SmsProperties;
import com.strade.auth_app.entity.NotificationQueue;
import com.strade.auth_app.exception.AuthException;
import com.strade.auth_app.exception.ErrorCode;
import com.strade.auth_app.repository.jpa.NotificationQueueRepository;
import com.strade.auth_app.util.JsonUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.time.LocalDateTime;
import java.util.*;

/**
 * SMS service with multiple provider support
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class SmsService {

    private final SmsProperties smsProperties;
    private final RestTemplate restTemplate;
    private final NotificationQueueRepository notificationQueueRepository;

    /**
     * Send OTP via SMS
     */
    public String sendOtp(String userId, String phoneNumber, String name, String otpCode) {
        UUID notificationId = UUID.randomUUID();

        try {
            log.info("Sending OTP SMS to {} for user {}", phoneNumber, userId);

            // 1. Create notification queue entry
            NotificationQueue notification = createNotificationQueue(
                    notificationId,
                    userId,
                    phoneNumber,
                    name,
                    otpCode
            );
            notificationQueueRepository.save(notification);

            // 2. Send via selected provider
            String messageId = switch (smsProperties.getProvider().toLowerCase()) {
                case "twilio" -> sendViaTwilio(phoneNumber, otpCode);
                //case "infobip" -> sendViaInfobip(phoneNumber, otpCode);
                //case "zenziva" -> sendViaZenziva(phoneNumber, otpCode);
                default -> throw new IllegalArgumentException("Unknown SMS provider: " + smsProperties.getProvider());
            };

            // 3. Update notification status to SENT
            notification.setStatus((byte) 1); // SENT
            notification.setSentAt(LocalDateTime.now());
            notificationQueueRepository.save(notification);

            log.info("OTP SMS sent successfully. NotificationId: {}, MessageId: {}",
                    notificationId, messageId);

            return messageId;

        } catch (Exception e) {
            log.error("Failed to send OTP SMS for user {}", userId, e);

            // Update notification status to FAILED
            notificationQueueRepository.findById(notificationId).ifPresent(notif -> {
                notif.setStatus((byte) 2); // FAILED
                notif.setErrorMessage(e.getMessage());
                notif.setRetryCount((byte) (notif.getRetryCount() + 1));
                notificationQueueRepository.save(notif);
            });

            throw new AuthException(ErrorCode.SMS_SEND_FAILED, "SMS send failed", e);
        }
    }

    /**
     * Send SMS via Twilio
     */
    private String sendViaTwilio(String phoneNumber, String otpCode) {
        try {
            String url = smsProperties.getTwilio().getBaseUrl() +
                    "/Accounts/" + smsProperties.getTwilio().getAccountSid() + "/Messages.json";

            // Prepare form data
            MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
            params.add("To", phoneNumber);
            params.add("From", smsProperties.getTwilio().getFromNumber());
            params.add("Body", buildSmsMessage(otpCode));

            // Prepare headers with Basic Auth
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            String auth = smsProperties.getTwilio().getAccountSid() + ":" +
                    smsProperties.getTwilio().getAuthToken();
            String encodedAuth = Base64.getEncoder().encodeToString(auth.getBytes());
            headers.set("Authorization", "Basic " + encodedAuth);

            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);

            ResponseEntity<Map> response = restTemplate.postForEntity(url, request, Map.class);

            if (response.getStatusCode() == HttpStatus.CREATED) {
                Map<String, Object> body = response.getBody();
                return body != null ? (String) body.get("sid") : null;
            }

            throw new RuntimeException("Twilio returned status: " + response.getStatusCode());

        } catch (Exception e) {
            log.error("Error sending SMS via Twilio", e);
            throw new RuntimeException("Twilio SMS failed", e);
        }
    }

    /**
     * Send SMS via Infobip
     */
//    private String sendViaInfobip(String phoneNumber, String otpCode) {
//        try {
//            String url = smsProperties.getInfobip().getBaseUrl() + "/sms/2/text/advanced";
//
//            // Prepare JSON body
//            Map<String, Object> payload = new HashMap<>();
//            payload.put("messages", List.of(
//                    Map.of(
//                            "from", smsProperties.getInfobip().getSender(),
//                            "destinations", List.of(Map.of("to", phoneNumber)),
//                            "text", buildSmsMessage(otpCode)
//                    )
//            ));
//
//            // Prepare headers
//            HttpHeaders headers = new HttpHeaders();
//            headers.setContentType(MediaType.APPLICATION_JSON);
//            headers.set("Authorization", "App " + smsProperties.getInfobip().getApiKey());
//
//            HttpEntity<Map<String, Object>> request = new HttpEntity<>(payload, headers);
//
//            ResponseEntity<Map> response = restTemplate.postForEntity(url, request, Map.class);
//
//            if (response.getStatusCode().is2xxSuccessful()) {
//                Map<String, Object> body = response.getBody();
//                if (body != null && body.containsKey("messages")) {
//                    List<Map<String, Object>> messages = (List<Map<String, Object>>) body.get("messages");
//                    if (!messages.isEmpty()) {
//                        return (String) messages.get(0).get("messageId");
//                    }
//                }
//            }
//
//            throw new RuntimeException("Infobip returned status: " + response.getStatusCode());
//
//        } catch (Exception e) {
//            log.error("Error sending SMS via Infobip", e);
//            throw new RuntimeException("Infobip SMS failed", e);
//        }
//    }

    /**
     * Send SMS via Zenziva (Indonesia local provider)
     */
//    private String sendViaZenziva(String phoneNumber, String otpCode) {
//        try {
//            String url = smsProperties.getZenziva().getBaseUrl() + "/sendsms";
//
//            // Prepare form data
//            MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
//            params.add("userkey", smsProperties.getZenziva().getUserKey());
//            params.add("passkey", smsProperties.getZenziva().getPassKey());
//            params.add("to", phoneNumber);
//            params.add("message", buildSmsMessage(otpCode));
//
//            HttpHeaders headers = new HttpHeaders();
//            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
//
//            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);
//
//            ResponseEntity<Map> response = restTemplate.postForEntity(url, request, Map.class);
//
//            if (response.getStatusCode().is2xxSuccessful()) {
//                Map<String, Object> body = response.getBody();
//                if (body != null && "0".equals(String.valueOf(body.get("status")))) {
//                    return (String) body.get("messageId");
//                }
//            }
//
//            throw new RuntimeException("Zenziva returned status: " + response.getStatusCode());
//
//        } catch (Exception e) {
//            log.error("Error sending SMS via Zenziva", e);
//            throw new RuntimeException("Zenziva SMS failed", e);
//        }
//    }

    /**
     * Create notification queue entry
     */
    private NotificationQueue createNotificationQueue(
            UUID notificationId,
            String userId,
            String phoneNumber,
            String name,
            String otpCode
    ) {
        Map<String, Object> templateData = new HashMap<>();
        templateData.put("phone_number", phoneNumber);
        templateData.put("name", name);
        templateData.put("otp_code", otpCode);
        templateData.put("provider", smsProperties.getProvider());

        return NotificationQueue.builder()
                .notificationId(notificationId)
                .userId(userId)
                .type("OTP_LOGIN_2FA")
                .channel("sms")
                .destination(phoneNumber)
                .subject("OTP Code")
                .body(buildSmsMessage(otpCode))
                .templateData(JsonUtil.toJson(templateData))
                .status((byte) 0)
                .retryCount((byte) 0)
                .createdAt(LocalDateTime.now())
                .build();
    }

    /**
     * Build SMS message
     */
    private String buildSmsMessage(String otpCode) {
        return String.format(
                "Your STRADE OTP code is: %s. Valid for 5 minutes. Do not share this code.",
                otpCode
        );
    }
}