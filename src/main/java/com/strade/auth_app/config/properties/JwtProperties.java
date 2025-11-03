package com.strade.auth_app.config.properties;

import lombok.Getter;
import lombok.Setter;

/**
 * JWT configuration properties
 */
@Getter
@Setter
public class JwtProperties {

    private String issuer = "strade-auth";
    private String privateKeyPath = "classpath:keys/private_key.pem";
    private String publicKeyPath = "classpath:keys/public_key.pem";

    private AccessTokenConfig accessToken = new AccessTokenConfig();
    private RefreshTokenConfig refreshToken = new RefreshTokenConfig();

    @Getter
    @Setter
    public static class AccessTokenConfig {
        private Integer expirationMinutes = 15;
    }

    @Getter
    @Setter
    public static class RefreshTokenConfig {
        private Integer expirationDays = 30;
    }
}