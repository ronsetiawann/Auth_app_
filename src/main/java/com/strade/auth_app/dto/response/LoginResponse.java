package com.strade.auth_app.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.UUID;

/**
 * Login response DTO
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class LoginResponse {

    private Boolean mfaRequired;
    private UUID sessionId;
    private List<String> availableMfaMethods;
    private TokenResponse tokens;
    private String message;

    /**
     * Create response for successful login (no MFA)
     */
    public static LoginResponse success(TokenResponse tokens, UUID sessionId, String message) {
        return LoginResponse.builder()
                .mfaRequired(false)
                .sessionId(sessionId)
                .tokens(tokens)
                .message(message)
                .build();
    }

    /**
     * Create response for MFA required
     */
    public static LoginResponse mfaRequired(UUID sessionId, List<String> availableMethods, String message) {
        return LoginResponse.builder()
                .mfaRequired(true)
                .sessionId(sessionId)
                .availableMfaMethods(availableMethods)
                .message(message)
                .build();
    }
}