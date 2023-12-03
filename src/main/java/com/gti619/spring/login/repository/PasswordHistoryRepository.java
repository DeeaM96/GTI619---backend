package com.gti619.spring.login.repository;

import com.gti619.spring.login.models.PasswordHistory;
import com.gti619.spring.login.models.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface PasswordHistoryRepository extends JpaRepository<PasswordHistory, Long> {
    List<PasswordHistory> findTop5ByUserOrderByChangeDateDesc(User user);
}
