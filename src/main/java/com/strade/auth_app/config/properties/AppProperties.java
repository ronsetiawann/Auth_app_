package com.strade.auth_app.config.properties;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Main application properties
 */
@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix = "app")
public class AppProperties {

    private String name = "STRADE Auth Service";
    private String version = "1.0.0";

    private JwtProperties jwt = new JwtProperties();
    private SecurityProperties security = new SecurityProperties();
}