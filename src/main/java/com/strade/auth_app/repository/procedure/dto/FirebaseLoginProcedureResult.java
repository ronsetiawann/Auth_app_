package com.strade.auth_app.repository.procedure.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

/**
 * Result from LoginIDXMobile stored procedure
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class FirebaseLoginProcedureResult {

    private Boolean isLoginSuccess;
    private String loginMessage;
    private Integer errCode;
    private UUID sessionId;
    private String kid;
    private Boolean mfaRequired;
}