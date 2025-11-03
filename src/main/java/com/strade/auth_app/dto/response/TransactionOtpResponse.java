package com.strade.auth_app.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TransactionOtpResponse {

    private UUID challengeId;
    private Integer expiresIn;
    private Integer attemptsRemaining;
    private String message;
}