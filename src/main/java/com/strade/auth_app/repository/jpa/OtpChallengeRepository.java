package com.strade.auth_app.repository.jpa;
import com.strade.auth_app.entity.OtpChallenge;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface OtpChallengeRepository extends JpaRepository<OtpChallenge, UUID> {

    @Query("SELECT o FROM OtpChallenge o WHERE o.userId = :userId " +
            "AND o.purpose = :purpose AND o.status = 0 " +
            "ORDER BY o.createdAt DESC")
    List<OtpChallenge> findPendingChallengesByUserIdAndPurpose(
            @Param("userId") String userId,
            @Param("purpose") String purpose
    );

    @Query("SELECT o FROM OtpChallenge o WHERE o.destination = :destination " +
            "AND o.channel = :channel AND o.status = 0 " +
            "AND o.expiresAt > :now AND o.codeHash = :codeHash " +
            "ORDER BY o.createdAt DESC")
    Optional<OtpChallenge> findMatchingChallenge(
            @Param("destination") String destination,
            @Param("channel") String channel,
            @Param("now") LocalDateTime now,
            @Param("codeHash") byte[] codeHash
    );

    Optional<OtpChallenge> findByChallengeId(UUID challengeId);

    @Query("UPDATE OtpChallenge o SET o.status = 2 WHERE o.status = 0 AND o.expiresAt < :now")
    void markExpiredChallenges(@Param("now") LocalDateTime now);

    void deleteByCreatedAtBefore(LocalDateTime threshold);
}
