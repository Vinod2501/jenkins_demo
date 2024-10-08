package com.epam.musicapp.user.management.repository;

import com.epam.musicapp.user.management.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUserEmail(String userEmail);
    Optional<User> findByUserName(String userName);
    boolean existsByUserName(String userName);

    boolean existsByUserEmail(String userEmail);
}
