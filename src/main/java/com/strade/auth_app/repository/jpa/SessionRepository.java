package com.strade.auth_app.repository.jpa;

import com.strade.auth_app.entity.Session;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface SessionRepository extends JpaRepository<Session, UUID> {

    Optional<Session> findBySessionId(UUID sessionId);

    boolean existsBySessionIdAndStatus(UUID sessionId, Byte status);

    @Query("SELECT s FROM Session s WHERE s.userId = :userId AND s.status = :status")
    List<Session> findByUserIdAndStatus(@Param("userId") String userId, @Param("status") Byte status);

    @Query("SELECT s FROM Session s WHERE s.userId = :userId AND s.status = 1")
    List<Session> findActiveSessionsByUserId(@Param("userId") String userId);

    @Query("SELECT COUNT(s) FROM Session s WHERE s.userId = :userId AND s.status = 1")
    long countActiveSessionsByUserId(@Param("userId") String userId);

    @Query("SELECT s FROM Session s WHERE s.userId = :userId AND s.channel = :channel AND s.status = 1")
    List<Session> findActiveSessionsByUserIdAndChannel(
            @Param("userId") String userId,
            @Param("channel") String channel
    );

    /**
     * Find sessions that are inactive
     * Status = ACTIVE, LastSeenAt < threshold
     */

    @Query("SELECT s FROM Session s " +
            "WHERE s.status = 1 " +
            "AND s.lastSeenAt < :threshold " +
            "AND (s.expiresAt IS NULL OR s.expiresAt > :now)")
    List<Session> findInactiveSessions(@Param("threshold") LocalDateTime threshold, @Param("now") LocalDateTime now
    );
}