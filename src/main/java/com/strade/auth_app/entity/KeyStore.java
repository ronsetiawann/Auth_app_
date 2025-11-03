package com.strade.auth_app.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

/**
 * JWT Public Key metadata for RS256 token verification
 * Maps to Auth.KeyStore table
 */
@Entity
@Table(name = "KeyStore", schema = "Auth")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class KeyStore {

    @Id
    @Column(name = "Kid", length = 64, nullable = false)
    private String kid;

    @Column(name = "Alg", length = 10, nullable = false)
    private String alg = "RS256";

    @Column(name = "PublicKeyPem", nullable = false, columnDefinition = "NVARCHAR(MAX)")
    private String publicKeyPem;

    @Column(name = "NotBefore")
    private LocalDateTime notBefore;

    @Column(name = "NotAfter")
    private LocalDateTime notAfter;

    @Column(name = "Active", nullable = false)
    private Boolean active = false;

    @Column(name = "CreatedAt", nullable = false)
    private LocalDateTime createdAt;

    @PrePersist
    protected void onCreate() {
        if (createdAt == null) {
            createdAt = LocalDateTime.now();
        }
    }
}
