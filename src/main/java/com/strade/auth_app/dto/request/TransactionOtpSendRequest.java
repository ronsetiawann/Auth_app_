package com.strade.auth_app.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;

/**
 * Request to send transaction OTP via WhatsApp
 * For stock trading transactions
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TransactionOtpSendRequest {

    @NotBlank(message = "Purpose is required")
    @Pattern(
            regexp = "^(buy_stock|sell_stock|withdrawal|deposit|fund_transfer)$",
            message = "Invalid transaction type. Must be: buy_stock, sell_stock, withdrawal, deposit, or fund_transfer"
    )
    private String purpose;
    @NotNull(message = "UserId is required")
    private String userId;
    private String clientId;
    private String reference;
}