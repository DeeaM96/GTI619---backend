package com.gti619.spring.login.repository;

import com.gti619.spring.login.models.PasswordHistory;
import com.gti619.spring.login.models.User;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface PasswordHistoryRepository extends JpaRepository<PasswordHistory, Long> {
    List<PasswordHistory> findTop5ByUserOrderByChangeDateDesc(User user);

      @Query("SELECT p FROM PasswordHistory p WHERE p.user = :user ORDER BY p.changeDate DESC")
        List<PasswordHistory> findTopNByUserOrderByChangeDateDesc(User user, Pageable pageable);


}
