package com.strade.auth_app.config.properties;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Email configuration properties
 */
@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix = "app.mail")
public class EmailProperties {

    private String host;
    private Integer port = 587;
    private String username;
    private String password;
    private String from = "8ed1b644362c4d@inbox.mailtrap.io";
    private String fromName = "STRADE";

    private Smtp smtp = new Smtp();

    @Getter
    @Setter
    public static class Smtp {
        private boolean auth = true;
        private boolean starttlsEnable = true;
        private boolean starttlsRequired = true;
        private Integer connectionTimeout = 5000;
        private Integer timeout = 5000;
        private Integer writeTimeout = 5000;
    }
}