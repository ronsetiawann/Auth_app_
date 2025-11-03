package com.strade.auth_app.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Firebase login request (IDX Mobile)
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class FirebaseLoginRequest {

    @NotBlank(message = "Firebase token is required")
    private String firebaseToken;

    @Size(max = 50, message = "Terminal must not exceed 50 characters")
    private String terminal;

    @NotBlank(message = "Channel is required")
    @Size(max = 50, message = "Channel must not exceed 50 characters")
    private String channel = "OT";

    @Size(max = 50, message = "Version must not exceed 50 characters")
    private String version;

    @Size(max = 100, message = "Device ID must not exceed 100 characters")
    private String deviceId;

    @Size(max = 200, message = "User agent must not exceed 200 characters")
    private String userAgent;
}
