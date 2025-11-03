package com.strade.auth_app.repository.jpa;

import com.strade.auth_app.entity.LoginShadow;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface LoginShadowRepository extends JpaRepository<LoginShadow, String> {

    Optional<LoginShadow> findByUserId(String userId);
}
