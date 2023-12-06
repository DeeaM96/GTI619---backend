package com.gti619.spring.login.repository;

import com.gti619.spring.login.models.UserActivityLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserActivityLogRepository extends JpaRepository<UserActivityLog, Long> {
}

