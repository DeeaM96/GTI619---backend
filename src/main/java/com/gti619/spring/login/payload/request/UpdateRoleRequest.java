package com.gti619.spring.login.payload.request;


import java.util.Set;

public class UpdateRoleRequest {
    private String username;
    private Set<String> newRoles;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public Set<String> getNewRoles() {
        return newRoles;
    }

    public void setNewRoles(Set<String> newRoles) {
        this.newRoles = newRoles;
    }
// Getters and setters
}