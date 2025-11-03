package com.strade.auth_app.repository.jpa;

import com.strade.auth_app.entity.UserMfa;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserMfaRepository extends JpaRepository<UserMfa, String> {

    Optional<UserMfa> findByUserId(String userId);

    boolean existsByUserIdAndTotpStatus(String userId, Byte status);
}