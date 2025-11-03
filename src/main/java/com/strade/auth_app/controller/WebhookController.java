package com.strade.auth_app.controller;

import com.strade.auth_app.dto.request.WhatsAppWebhookRequest;
import com.strade.auth_app.repository.procedure.MfaProcedureRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Webhook REST API Controller
 * For receiving callbacks from external providers
 */
@RestController
@RequestMapping("/api/v1/webhook")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Webhooks", description = "Webhook APIs for external providers")
public class WebhookController {

    private final MfaProcedureRepository mfaProcedureRepository;

    /**
     * Mekari Qontak WhatsApp webhook
     * POST /api/v1/webhook/whatsapp/mekari
     * NOTE: This is for future implementation when Mekari supports incoming message webhook
     */
    @PostMapping("/whatsapp/mekari")
    @Operation(
            summary = "Mekari WhatsApp webhook",
            description = "Receive incoming WhatsApp messages from Mekari Qontak (Future feature)"
    )
    public ResponseEntity<String> handleMekariWhatsAppWebhook(
            @RequestBody Map<String, Object> payload
    ) {
        log.info("Received Mekari WhatsApp webhook: {}", payload);

        try {
            String fromNumber = (String) payload.get("from");
            String messageText = (String) payload.get("body");
            String messageId = (String) payload.get("message_id");

            if (fromNumber == null || messageText == null) {
                log.warn("Invalid webhook payload: missing required fields");
                return ResponseEntity.ok("INVALID_PAYLOAD");
            }

            // Call stored procedure to process incoming OTP
            mfaProcedureRepository.processIncomingWhatsAppOtp(
                    fromNumber,
                    messageText,
                    messageId
            );

            log.info("WhatsApp OTP processed successfully from: {}", fromNumber);
            return ResponseEntity.ok("OK");

        } catch (Exception e) {
            log.error("Error processing WhatsApp webhook", e);
            // Return 200 to prevent provider retry
            return ResponseEntity.ok("ERROR");
        }
    }

    /**
     * Twilio WhatsApp webhook (Alternative provider)
     *
     * POST /api/v1/webhook/whatsapp/twilio
     */
    @PostMapping("/whatsapp/twilio")
    @Operation(
            summary = "Twilio WhatsApp webhook",
            description = "Receive incoming WhatsApp messages from Twilio (Future feature)"
    )
    public ResponseEntity<String> handleTwilioWhatsAppWebhook(
            @RequestParam("From") String from,
            @RequestParam("Body") String body,
            @RequestParam(value = "MessageSid", required = false) String messageSid
    ) {
        log.info("Received Twilio WhatsApp webhook from: {}", from);

        try {
            // Remove "whatsapp:" prefix
            String phoneNumber = from.replace("whatsapp:", "");

            mfaProcedureRepository.processIncomingWhatsAppOtp(
                    phoneNumber,
                    body,
                    messageSid
            );

            log.info("WhatsApp OTP processed successfully from: {}", phoneNumber);
            return ResponseEntity.ok("OK");

        } catch (Exception e) {
            log.error("Error processing Twilio WhatsApp webhook", e);
            return ResponseEntity.ok("ERROR");
        }
    }
}
