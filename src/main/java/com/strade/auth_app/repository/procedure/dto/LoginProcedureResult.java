package com.strade.auth_app.repository.procedure.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

/**
 * Result from SelectUser_Logon stored procedure
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LoginProcedureResult {

    private Boolean isLoginSuccess;
    private String loginMessage;
    private Integer errCode;
    private String dbVersion;
    private String channel;
    private UUID sessionId;
    private String kid;
    private Boolean mfaRequired;
    private String myToken;
}
