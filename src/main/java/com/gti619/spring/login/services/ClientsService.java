package com.gti619.spring.login.service;

import com.gti619.spring.login.models.Clients;
import com.gti619.spring.login.repository.ClientsRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class ClientsService {

    @Autowired
    private ClientsRepository clientsRepository;

    public Page<Clients> findAllClients(Pageable pageable) {
        return clientsRepository.findAll(pageable);
    }

    public Page<Clients> findClientsByType(int type, Pageable pageable) {
        return clientsRepository.findByType(type, pageable);
    }
}
