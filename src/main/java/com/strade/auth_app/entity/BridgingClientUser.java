package com.strade.auth_app.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "BridgingClientUser", schema = "dbo")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class BridgingClientUser {
    @Id
    @Column(name = "ClientID", length = 30)
    private String clientId;

    @Column(name = "DealerID", length = 30)
    private String dealerId;

    @Column(name = "AutoUpdate")
    private boolean autoUpdate;

    @Column(name = "LastUpdate")
    private LocalDateTime lastUpdate;

}
