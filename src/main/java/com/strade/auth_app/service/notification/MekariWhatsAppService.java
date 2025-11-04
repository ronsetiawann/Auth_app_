package com.strade.auth_app.service.notification;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.strade.auth_app.config.properties.MekariProperties;
import com.strade.auth_app.dto.request.MekariWhatsAppRequest;
import com.strade.auth_app.dto.request.TransactionOtpSendRequest;
import com.strade.auth_app.entity.NotificationQueue;
import com.strade.auth_app.exception.AuthException;
import com.strade.auth_app.exception.ErrorCode;
import com.strade.auth_app.repository.jpa.NotificationQueueRepository;
import com.strade.auth_app.util.JsonUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.time.LocalDateTime;
import java.util.*;

/**
 * Mekari Qontak WhatsApp service
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class MekariWhatsAppService {

    private final MekariProperties mekariProperties;
    private final RestTemplate restTemplate;
    private final NotificationQueueRepository notificationQueueRepository;
    private final ObjectMapper objectMapper;

    /**
     * Send OTP via Mekari Qontak WhatsApp (for Login 2FA)
     */
    public String sendOtp(String userId, String phoneNumber, String name, String otpCode) {
        UUID notificationId = UUID.randomUUID();

        try {
            log.info("Sending WhatsApp OTP to {} for user {}", phoneNumber, userId);

            // Format phone
            String formattedPhone = formatPhoneNumber(phoneNumber);

            // 1. Create notification queue entry (PENDING)
            NotificationQueue notification = createNotificationQueue(
                    notificationId,
                    userId,
                    formattedPhone,
                    name,
                    otpCode
            );
            notificationQueueRepository.save(notification);

            // 2. Send to Mekari
            String path = "/qontak/chat/v1/broadcasts/whatsapp/direct";
            Map<String, String> headers = generateHmacHeaders("POST", path);

            MekariWhatsAppRequest request = buildOtpRequest(formattedPhone, name, otpCode);

            HttpEntity<MekariWhatsAppRequest> entity = new HttpEntity<>(
                    request,
                    buildHttpHeaders(headers)
            );

            ResponseEntity<String> response = restTemplate.exchange(
                    mekariProperties.getBaseUrl() + path,
                    HttpMethod.POST,
                    entity,
                    String.class
            );

            // 3. Check response
            if (response.getStatusCode() == HttpStatus.CREATED) {
                String broadcastId = extractBroadcastId(response.getBody());

                // 4. Update notification status to SENT
                notification.setStatus((byte) 1);
                notification.setSentAt(LocalDateTime.now());
                notificationQueueRepository.save(notification);

                log.info("WhatsApp OTP sent successfully. NotificationId: {}, BroadcastId: {}",
                        notificationId, broadcastId);

                return broadcastId;
            } else {
                throw new AuthException(
                        ErrorCode.WHATSAPP_SEND_FAILED,
                        "Mekari returned status: " + response.getStatusCode()
                );
            }

        } catch (Exception e) {
            log.error("Failed to send WhatsApp OTP for user {}", userId, e);

            // Update notification status to FAILED
            notificationQueueRepository.findById(notificationId).ifPresent(notif -> {
                notif.setStatus((byte) 2);
                notif.setErrorMessage(e.getMessage());
                notif.setRetryCount((byte) (notif.getRetryCount() + 1));
                notificationQueueRepository.save(notif);
            });

            throw new AuthException(ErrorCode.WHATSAPP_SEND_FAILED, "WhatsApp send failed", e);
        }
    }

    /**
     * Send transaction OTP via WhatsApp - Stock Trading
     */
    public String sendTransactionOtp(
            String userId,
            String phoneNumber,
            String name,
            String otpCode,
            TransactionOtpSendRequest transactionRequest
    ) {
        UUID notificationId = UUID.randomUUID();

        try {
            log.info("Sending transaction OTP to {} for user {}", phoneNumber, userId);

            // Format phone
            String formattedPhone = formatPhoneNumber(phoneNumber);

            // Create notification queue
            NotificationQueue notification = createTransactionNotificationQueue(
                    notificationId, userId, formattedPhone, name, otpCode, transactionRequest
            );
            notificationQueueRepository.save(notification);

            // Send via Mekari using template
            String path = "/qontak/chat/v1/broadcasts/whatsapp/direct";
            Map<String, String> headers = generateHmacHeaders("POST", path);

            // Build request using template (same structure as login OTP)
            MekariWhatsAppRequest request = buildOtpRequest(formattedPhone, name, otpCode);

            HttpEntity<MekariWhatsAppRequest> entity = new HttpEntity<>(
                    request,
                    buildHttpHeaders(headers)
            );

            ResponseEntity<String> response = restTemplate.exchange(
                    mekariProperties.getBaseUrl() + path,
                    HttpMethod.POST,
                    entity,
                    String.class
            );

            // Check response
            if (response.getStatusCode() == HttpStatus.CREATED) {
                String broadcastId = extractBroadcastId(response.getBody());

                // Update status to SENT
                notification.setStatus((byte) 1);
                notification.setSentAt(LocalDateTime.now());
                notificationQueueRepository.save(notification);

                log.info("Transaction OTP sent successfully: broadcastId={}", broadcastId);
                return broadcastId;
            } else {
                throw new AuthException(
                        ErrorCode.WHATSAPP_SEND_FAILED,
                        "Mekari returned status: " + response.getStatusCode()
                );
            }

        } catch (Exception e) {
            log.error("Failed to send transaction OTP", e);

            notificationQueueRepository.findById(notificationId).ifPresent(notif -> {
                notif.setStatus((byte) 2);
                notif.setErrorMessage(e.getMessage());
                notif.setRetryCount((byte) (notif.getRetryCount() + 1));
                notificationQueueRepository.save(notif);
            });

            throw new AuthException(
                    ErrorCode.WHATSAPP_SEND_FAILED,
                    "Failed to send transaction OTP",
                    e
            );
        }
    }

    /**
     * Create notification queue entry (for Login 2FA)
     */
    private NotificationQueue createNotificationQueue(
            UUID notificationId,
            String userId,
            String phoneNumber,
            String name,
            String otpCode
    ) {
        Map<String, Object> templateData = new HashMap<>();
        templateData.put("to_number", phoneNumber);
        templateData.put("to_name", name);
        templateData.put("otp_code", otpCode);
        templateData.put("template_id", mekariProperties.getWhatsapp().getTemplateId());

        return NotificationQueue.builder()
                .notificationId(notificationId)
                .userId(userId)
                .type("OTP_LOGIN_2FA")
                .channel("whatsapp")
                .destination(phoneNumber)
                .subject("Login OTP")
                .body("Your OTP code is: " + otpCode)
                .templateData(JsonUtil.toJson(templateData))
                .status((byte) 0)
                .retryCount((byte) 0)
                .createdAt(LocalDateTime.now())
                .build();
    }

    /**
     * Create notification queue for transaction OTP
     */
    private NotificationQueue createTransactionNotificationQueue(
            UUID notificationId,
            String userId,
            String phoneNumber,
            String name,
            String otpCode,
            TransactionOtpSendRequest request
    ) {
        Map<String, Object> templateData = new HashMap<>();
        templateData.put("phone_number", phoneNumber);
        templateData.put("name", name);
        templateData.put("otp_code", otpCode);
        templateData.put("purpose", request.getPurpose());

        // Add reference if provided
        if (request.getReference() != null && !request.getReference().isEmpty()) {
            templateData.put("reference", request.getReference());
        }

        return NotificationQueue.builder()
                .notificationId(notificationId)
                .userId(userId)
                .type("OTP_TRANSACTION_" + request.getPurpose().toUpperCase())
                .channel("whatsapp")
                .destination(phoneNumber)
                .subject("Transaction OTP")
                .body("Transaction OTP code: " + otpCode)
                .templateData(JsonUtil.toJson(templateData))
                .status((byte) 0)
                .retryCount((byte) 0)
                .createdAt(LocalDateTime.now())
                .build();
    }

    /**
     * Build Mekari WhatsApp request for OTP (Both Login & Transaction)
     * Template structure matches Mekari's requirement
     */
    private MekariWhatsAppRequest buildOtpRequest(String phoneNumber, String name, String otpCode) {
        MekariWhatsAppRequest request = new MekariWhatsAppRequest();
        request.setTo_number(phoneNumber);
        request.setTo_name(name);
        request.setMessage_template_id(mekariProperties.getWhatsapp().getTemplateId());
        request.setChannel_integration_id(mekariProperties.getWhatsapp().getChannelIntegrationId());

        // Language
        MekariWhatsAppRequest.Language language = new MekariWhatsAppRequest.Language();
        language.setCode("id");
        request.setLanguage(language);

        // Parameters
        MekariWhatsAppRequest.Parameters params = new MekariWhatsAppRequest.Parameters();

        // Body parameter - hanya OTP code
        MekariWhatsAppRequest.BodyParameter bodyParam = new MekariWhatsAppRequest.BodyParameter();
        bodyParam.setKey("1");
        bodyParam.setValue("code"); // sesuai dengan template variable name
        bodyParam.setValue_text(otpCode);
        params.setBody(List.of(bodyParam));

        // Button parameter - untuk autofill OTP
        MekariWhatsAppRequest.ButtonParameter buttonParam = new MekariWhatsAppRequest.ButtonParameter();
        buttonParam.setIndex("0");
        buttonParam.setType("url");
        buttonParam.setValue(otpCode);
        params.setButtons(List.of(buttonParam));

        request.setParameters(params);

        return request;
    }

    /**
     * Generate HMAC-SHA256 signature headers
     */
    private Map<String, String> generateHmacHeaders(String method, String path) {
        try {
            SimpleDateFormat dateFormat = new SimpleDateFormat(
                    "EEE, dd MMM yyyy HH:mm:ss 'GMT'",
                    Locale.US
            );
            dateFormat.setTimeZone(TimeZone.getTimeZone("GMT"));
            String dateTime = dateFormat.format(new Date());

            String requestLine = method + " " + path + " HTTP/1.1";
            String signingString = "date: " + dateTime + "\n" + requestLine;

            Mac hmac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKey = new SecretKeySpec(
                    mekariProperties.getClientSecret().getBytes(StandardCharsets.UTF_8),
                    "HmacSHA256"
            );
            hmac.init(secretKey);
            byte[] signatureBytes = hmac.doFinal(signingString.getBytes(StandardCharsets.UTF_8));
            String signature = Base64.getEncoder().encodeToString(signatureBytes);

            String authHeader = String.format(
                    "hmac username=\"%s\", algorithm=\"hmac-sha256\", headers=\"date request-line\", signature=\"%s\"",
                    mekariProperties.getClientId(),
                    signature
            );

            Map<String, String> headers = new HashMap<>();
            headers.put("Authorization", authHeader);
            headers.put("Date", dateTime);
            headers.put("Content-Type", "application/json");

            return headers;

        } catch (Exception e) {
            throw new RuntimeException("Failed to generate HMAC headers", e);
        }
    }

    /**
     * Build HTTP headers from map
     */
    private HttpHeaders buildHttpHeaders(Map<String, String> headerMap) {
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", headerMap.get("Authorization"));
        headers.set("Date", headerMap.get("Date"));
        headers.setContentType(MediaType.APPLICATION_JSON);
        return headers;
    }

    /**
     * Extract broadcast ID from Mekari response
     */
    private String extractBroadcastId(String responseBody) {
        try {
            JsonNode jsonNode = objectMapper.readTree(responseBody);
            // Akses data.id sesuai struktur response
            if (jsonNode.has("data")) {
                JsonNode dataNode = jsonNode.get("data");
                if (dataNode.has("id")) {
                    return dataNode.get("id").asText();
                }
            }
            log.warn("Broadcast ID not found in response: {}", responseBody);
            return null;
        } catch (Exception e) {
            log.error("Failed to parse broadcast ID from response", e);
            return null;
        }
    }

    /**
     * Check broadcast log/status
     */
    public Map<String, Object> getBroadcastLog(String broadcastId) {
        try {
            String path = "/qontak/chat/v1/broadcasts/" + broadcastId + "/whatsapp/log";
            Map<String, String> headers = generateHmacHeaders("GET", path);

            HttpEntity<Void> entity = new HttpEntity<>(buildHttpHeaders(headers));

            ResponseEntity<String> response = restTemplate.exchange(
                    mekariProperties.getBaseUrl() + path,
                    HttpMethod.GET,
                    entity,
                    String.class
            );

            if (response.getStatusCode().is2xxSuccessful()) {
                return JsonUtil.toMap(response.getBody());
            }

            return Map.of("error", "Failed to get broadcast log");

        } catch (Exception e) {
            log.error("Failed to get broadcast log for ID: {}", broadcastId, e);
            return Map.of("error", e.getMessage());
        }
    }

    /**
     * Format phone number for Mekari Qontak
     */
    private String formatPhoneNumber(String phoneNumber) {
        if (phoneNumber == null || phoneNumber.isEmpty()) {
            throw new AuthException(
                    ErrorCode.INVALID_REQUEST,
                    "Phone number is required"
            );
        }

        // Remove all non-numeric characters
        String cleaned = phoneNumber.replaceAll("[^0-9]", "");

        // Handle different formats
        if (cleaned.startsWith("0")) {
            // 08123456789 -> 628123456789
            return "62" + cleaned.substring(1);
        } else if (cleaned.startsWith("62")) {
            // 628123456789 -> 628123456789 (already correct)
            return cleaned;
        } else if (cleaned.startsWith("8")) {
            // 8123456789 -> 628123456789
            return "62" + cleaned;
        } else {
            throw new AuthException(
                    ErrorCode.INVALID_REQUEST,
                    "Invalid phone number format"
            );
        }
    }
}