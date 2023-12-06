package com.gti619.spring.login.services;

import com.gti619.spring.login.models.SecurityConfig;
import com.gti619.spring.login.repository.SecurityConfigRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class SecurityConfigService {

    @Autowired
    private SecurityConfigRepository securityConfigRepository;

    public void updateConfig(String configName, String configValue) {
        SecurityConfig config = securityConfigRepository.findByConfigName(configName)
                .orElse(new SecurityConfig());
        config.setConfigName(configName);
        config.setConfigValue(configValue);
        securityConfigRepository.save(config);
    }

    public String getConfigValue(String configName) {
        return securityConfigRepository.findByConfigName(configName)
                .map(SecurityConfig::getConfigValue)
                .orElse(null);
    }

    public Map<String, String> getAllConfigValues() {
        List<SecurityConfig> configs = securityConfigRepository.findAll();
        Map<String, String> settings = new HashMap<>();
        for (SecurityConfig config : configs) {
            settings.put(config.getConfigName(), config.getConfigValue());
        }
        return settings;
    }
}
