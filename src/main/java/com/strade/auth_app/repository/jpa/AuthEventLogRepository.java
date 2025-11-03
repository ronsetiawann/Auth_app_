package com.strade.auth_app.repository.jpa;

import com.strade.auth_app.entity.AuthEventLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Repository
public interface AuthEventLogRepository extends JpaRepository<AuthEventLog, UUID> {

    @Query("SELECT a FROM AuthEventLog a WHERE a.userId = :userId ORDER BY a.eventTime DESC")
    List<AuthEventLog> findByUserIdOrderByEventTimeDesc(@Param("userId") String userId);

    @Query("SELECT a FROM AuthEventLog a WHERE a.sessionId = :sessionId ORDER BY a.eventTime ASC")
    List<AuthEventLog> findBySessionIdOrderByEventTimeAsc(@Param("sessionId") UUID sessionId);

    @Query("SELECT a FROM AuthEventLog a WHERE a.eventType = :eventType " +
            "AND a.eventTime > :since ORDER BY a.eventTime DESC")
    List<AuthEventLog> findByEventTypeAndEventTimeAfter(
            @Param("eventType") String eventType,
            @Param("since") LocalDateTime since
    );
}
