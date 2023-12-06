package com.gti619.spring.login.controllers;

import com.gti619.spring.login.services.SecurityConfigService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@CrossOrigin(origins = {"http://localhost:4200", "https://localhost:4200"}, maxAge = 3600, allowCredentials = "true")
@RequestMapping("/api/security-settings")
public class SecurityConfigController {

    @Autowired
    private SecurityConfigService securityConfigService;

    @PostMapping("/updateSettings")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public ResponseEntity<?> updateSettings(@RequestBody Map<String, String> settings) {
        System.out.println("TEEEEEEEEST");
        settings.forEach(securityConfigService::updateConfig);
        return ResponseEntity.ok().build();
    }


    @GetMapping
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public ResponseEntity<Map<String, String>> getSettings() {
        Map<String, String> settings = securityConfigService.getAllConfigValues();
        return ResponseEntity.ok(settings);
    }
}
