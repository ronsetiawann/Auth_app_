package com.strade.auth_app.repository.jpa;
import com.strade.auth_app.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

    Optional<RefreshToken> findByTokenHash(byte[] tokenHash);

    @Query("SELECT rt FROM RefreshToken rt WHERE rt.sessionId = :sessionId AND rt.revokedAt IS NULL")
    List<RefreshToken> findActiveTokensBySessionId(@Param("sessionId") UUID sessionId);

    @Query("SELECT rt FROM RefreshToken rt WHERE rt.revokedAt IS NOT NULL AND rt.revokedAt < :threshold")
    List<RefreshToken> findRevokedTokensOlderThan(@Param("threshold") LocalDateTime threshold);

    void deleteByRevokedAtIsNotNullAndRevokedAtBefore(LocalDateTime threshold);
}
