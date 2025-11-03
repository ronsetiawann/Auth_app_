package com.strade.auth_app.repository.jpa;

import com.strade.auth_app.entity.UserMfaBackupCode;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface UserMfaBackupCodeRepository extends JpaRepository<UserMfaBackupCode, UUID> {

    @Query("SELECT b FROM UserMfaBackupCode b WHERE b.userId = :userId AND b.usedAt IS NULL")
    List<UserMfaBackupCode> findAvailableCodesByUserId(@Param("userId") String userId);

    @Query("SELECT COUNT(b) FROM UserMfaBackupCode b WHERE b.userId = :userId AND b.usedAt IS NULL")
    long countAvailableCodesByUserId(@Param("userId") String userId);

    void deleteByUserId(String userId);
}
