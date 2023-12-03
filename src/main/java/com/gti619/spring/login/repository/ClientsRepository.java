package com.gti619.spring.login.repository;

import com.gti619.spring.login.models.Clients;
import com.gti619.spring.login.models.User;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;



@Repository
public interface ClientsRepository extends JpaRepository<Clients, Long> {
    Page<Clients> findByType(int type, Pageable pageable);
}
