package com.strade.auth_app.config.properties;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Mekari Qontak API configuration properties
 */
@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix = "mekari")
public class MekariProperties {

    private String clientId;
    private String clientSecret;
    private String baseUrl = "https://api.mekari.com";

    private WhatsAppConfig whatsapp = new WhatsAppConfig();

    @Getter
    @Setter
    public static class WhatsAppConfig {
        private String templateId;
        private String channelIntegrationId;
    }
}