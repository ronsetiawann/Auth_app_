package com.strade.auth_app.repository.jpa;

import com.strade.auth_app.entity.NotificationQueue;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Repository
public interface NotificationQueueRepository extends JpaRepository<NotificationQueue, UUID> {

    @Query(value = "SELECT TOP :batchSize * FROM Auth.NotificationQueue " +
            "WHERE Status = 0 AND CreatedAt > :threshold " +
            "ORDER BY CreatedAt ASC",
            nativeQuery = true)
    List<NotificationQueue> findPendingNotifications(
            @Param("batchSize") int batchSize,
            @Param("threshold") LocalDateTime threshold
    );

    void deleteByStatusInAndCreatedAtBefore(List<Byte> statuses, LocalDateTime threshold);
}
