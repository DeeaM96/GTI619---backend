package com.gti619.spring.login.controllers;

import com.gti619.spring.login.models.User;
import com.gti619.spring.login.payload.response.UserInfoResponse;
import com.gti619.spring.login.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@CrossOrigin(origins = "http://localhost:4200", maxAge = 3600, allowCredentials="true")
@RequestMapping("/api/utilisateurs")
@RestController
public class UserController {
    @Autowired
    private UserService userService;


    @GetMapping("/get")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public ResponseEntity<List<UserInfoResponse>> getAllUsers() {
        List<UserInfoResponse> users = userService.getAllUsers();
        return ResponseEntity.ok(users);
    }
}
