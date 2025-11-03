package com.strade.auth_app.repository.jpa;

import com.strade.auth_app.entity.LogLogin;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface LogLoginRepository extends JpaRepository<LogLogin, String> {
    Optional<LogLogin> findByUserId(String userId);
}
