package com.strade.auth_app.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

/**
 * OTP challenge response
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class OtpChallengeResponse {

    private UUID challengeId;
    private Integer expiresIn;           // Seconds until expiration
    private Integer attemptsRemaining;
    private String maskedDestination;    // Masked phone/email
    private String message;
}
