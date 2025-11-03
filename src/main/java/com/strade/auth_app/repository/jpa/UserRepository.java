package com.strade.auth_app.repository.jpa;

import com.strade.auth_app.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, String> {

    Optional<User> findByUserId(String userId);

    @Query("SELECT u FROM User u WHERE u.userId = :userId AND u.type = 0")
    Optional<User> findActiveUserByUserId(@Param("userId") String userId);

}