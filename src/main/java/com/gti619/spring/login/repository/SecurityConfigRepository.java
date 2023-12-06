package com.gti619.spring.login.repository;


import com.gti619.spring.login.models.SecurityConfig;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface SecurityConfigRepository extends JpaRepository<SecurityConfig, Integer> {
    Optional<SecurityConfig> findByConfigName(String configName);
}
