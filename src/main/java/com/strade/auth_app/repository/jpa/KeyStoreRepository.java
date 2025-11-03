package com.strade.auth_app.repository.jpa;

import com.strade.auth_app.entity.KeyStore;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface KeyStoreRepository extends JpaRepository<KeyStore, String> {

    @Query("SELECT k FROM KeyStore k WHERE k.active = true ORDER BY k.createdAt DESC")
    Optional<KeyStore> findActiveKey();

    Optional<KeyStore> findByKid(String kid);
}
