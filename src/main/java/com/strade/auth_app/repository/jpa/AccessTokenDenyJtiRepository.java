package com.strade.auth_app.repository.jpa;

import com.strade.auth_app.entity.AccessTokenDenyJti;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;

@Repository
public interface AccessTokenDenyJtiRepository extends JpaRepository<AccessTokenDenyJti, String> {

    @Query("SELECT CASE WHEN COUNT(a) > 0 THEN true ELSE false END " +
            "FROM AccessTokenDenyJti a WHERE a.jti = :jti AND a.expiresAt > :now")
    boolean existsByJtiAndExpiresAtAfter(@Param("jti") String jti, @Param("now") LocalDateTime now);

    void deleteByExpiresAtBefore(LocalDateTime threshold);
}