package com.strade.auth_app.repository.jpa;

import com.strade.auth_app.entity.BridgingClientUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface BridgingClientUserRepository extends JpaRepository<BridgingClientUser, String> {
    Optional<BridgingClientUser> findByClientId(String clientId);
    Optional<BridgingClientUser> findByDealerId(String dealerId);
}
