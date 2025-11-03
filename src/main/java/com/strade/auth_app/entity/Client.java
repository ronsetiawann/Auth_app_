package com.strade.auth_app.entity;

import jakarta.persistence.*;
import lombok.*;

/**
 * Client View Entity - Read-only
 * Maps to SL.SClientView
 */
@Entity
@Table(name = "SClientView", schema = "SL")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Client {

    @Id
    @Column(name = "ClientID", length = 30)
    private String clientId;

    @Column(name = "Phone", length = 20)
    private String phone;

    @Column(name = "Email", length = 100)
    private String email;

    @Column(name = "KTP", length = 50)
    private String ktp;

    @Column(name = "NPWP", length = 50)
    private String npwp;

    @Column(name = "KSEIID", length = 50)
    private String kseiId;

    @Column(name = "CBESTAccount", length = 50)
    private String cbestAccount;

    @Column(name = "Contacts", length = 200)
    private String contacts;

    @Column(name = "RDNBank", length = 50)
    private String rdnBank;

    @Column(name = "RDNAccountName", length = 100)
    private String rdnAccountName;

    @Column(name = "RDNAccountNo", length = 50)
    private String rdnAccountNo;

    @Column(name = "PrivateBank", length = 50)
    private String privateBank;

    @Column(name = "PrivateAccountName", length = 100)
    private String privateAccountName;

    @Column(name = "PrivateAccountNo", length = 50)
    private String privateAccountNo;

    @Column(name = "Interbank", length = 50)
    private String interbank;

    /**
     * Get display name (use Contacts or ClientID)
     */
    public String getDisplayName() {
        return contacts != null && !contacts.isEmpty() ? contacts : clientId;
    }

    /**
     * Get formatted phone with country code
     */
    public String getFormattedPhone() {
        if (phone == null || phone.isEmpty()) {
            return null;
        }

        // Already has country code
        if (phone.startsWith("+") || phone.startsWith("62")) {
            return phone;
        }

        // Remove leading 0 and add Indonesia code
        if (phone.startsWith("0")) {
            return "62" + phone.substring(1);
        }

        return "62" + phone;
    }
}