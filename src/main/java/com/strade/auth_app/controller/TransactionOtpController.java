package com.strade.auth_app.controller;

import com.strade.auth_app.dto.request.TransactionOtpSendRequest;
import com.strade.auth_app.dto.request.TransactionOtpVerifyRequest;
import com.strade.auth_app.dto.response.ApiResponse;
import com.strade.auth_app.dto.response.TransactionOtpResponse;
import com.strade.auth_app.service.TransactionOtpService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * Transaction OTP Controller
 * Handles OTP verification for stock trading transactions
 */
@RestController
@RequestMapping("/api/v1/transaction/otp")
@RequiredArgsConstructor
@Slf4j
@Tag(
        name = "Transaction OTP",
        description = "Transaction OTP verification for stock trading (Buy/Sell/Withdrawal/Deposit)"
)
@SecurityRequirement(name = "bearerAuth")
public class TransactionOtpController {

    private final TransactionOtpService transactionOtpService;

    /**
     * Send transaction OTP via WhatsApp
     *
     * @param request Transaction OTP send request
     * @return Transaction OTP response with challengeId
     */
    @PostMapping("/send")
    public ResponseEntity<ApiResponse<TransactionOtpResponse>> sendTransactionOtp(
            @Valid @RequestBody TransactionOtpSendRequest request
    ) {
        log.info("Transaction OTP send request: purpose={}, reference={}",
                request.getPurpose(),
                request.getReference());

        TransactionOtpResponse response = transactionOtpService.sendTransactionOtp(request);

        log.info("Transaction OTP sent successfully: challengeId={}", response.getChallengeId());

        return ResponseEntity.ok(ApiResponse.success(response));
    }

    /**
     * Verify transaction OTP code
     *
     * @param request Transaction OTP verify request
     * @return Success response if OTP is valid
     */
    @PostMapping("/verify")
    public ResponseEntity<ApiResponse<Void>> verifyTransactionOtp(
            @Valid @RequestBody TransactionOtpVerifyRequest request
    ) {
        log.info("Transaction OTP verification request: challengeId={}",
                request.getChallengeId());

        transactionOtpService.verifyTransactionOtp(request);

        log.info("Transaction OTP verified successfully: challengeId={}",
                request.getChallengeId());

        return ResponseEntity.ok(ApiResponse.success(null));
    }
}