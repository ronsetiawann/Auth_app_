package com.strade.auth_app.repository.jpa;

import com.strade.auth_app.entity.TrustedDevice;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface TrustedDeviceRepository extends JpaRepository<TrustedDevice, UUID> {

    @Query("SELECT CASE WHEN COUNT(td) > 0 THEN true ELSE false END " +
            "FROM TrustedDevice td WHERE td.userId = :userId " +
            "AND td.deviceId = :deviceId " +
            "AND (td.trustedChannel IS NULL OR td.trustedChannel = :channel) " +
            "AND td.trustedRevokedAt IS NULL " +
            "AND (td.trustedUntil IS NULL OR td.trustedUntil > :now)")
    boolean existsActiveTrustedDevice(
            @Param("userId") String userId,
            @Param("deviceId") String deviceId,
            @Param("channel") String channel,
            @Param("now") LocalDateTime now
    );

    @Query("SELECT td FROM TrustedDevice td WHERE td.userId = :userId " +
            "AND td.trustedRevokedAt IS NULL " +
            "AND (td.trustedUntil IS NULL OR td.trustedUntil > :now)")
    List<TrustedDevice> findActiveTrustedDevicesByUserId(
            @Param("userId") String userId,
            @Param("now") LocalDateTime now
    );

    @Query("SELECT COUNT(td) FROM TrustedDevice td WHERE td.userId = :userId " +
            "AND td.trustedRevokedAt IS NULL " +
            "AND (td.trustedUntil IS NULL OR td.trustedUntil > :now)")
    long countActiveTrustedDevicesByUserId(
            @Param("userId") String userId,
            @Param("now") LocalDateTime now
    );

    Optional<TrustedDevice> findByUserIdAndDeviceIdAndTrustedChannel(
            String userId,
            String deviceId,
            String trustedChannel
    );
}
