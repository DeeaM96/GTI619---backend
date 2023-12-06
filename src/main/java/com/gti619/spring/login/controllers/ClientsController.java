package com.gti619.spring.login.controllers;

import com.gti619.spring.login.models.Clients;
import com.gti619.spring.login.service.ClientsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@CrossOrigin(origins = {"http://localhost:4200", "https://localhost:4200"}, maxAge = 3600, allowCredentials="true")

@RestController
@RequestMapping("/api/clients")
public class ClientsController {

    @Autowired
    private ClientsService clientsService;

    @GetMapping
    public Page<Clients> getAllClients(Pageable pageable) {
        return clientsService.findAllClients(pageable);
    }

    @GetMapping("/type/residential")
    @PreAuthorize("hasRole('ROLE_PREP_RES') or hasRole('ROLE_ADMIN')  ")
    public Page<Clients> getClientsResidential( Pageable pageable) {
        return clientsService.findClientsByType(1, pageable);
    }
    @GetMapping("/type/affaire")
    @PreAuthorize("hasRole('ROLE_PREP_AFF') or hasRole('ROLE_ADMIN') ")
    public Page<Clients> getClientsAffaire( Pageable pageable) {
        return clientsService.findClientsByType(2, pageable);
    }

}
