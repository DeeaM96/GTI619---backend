package com.gti619.spring.login.services;

import com.gti619.spring.login.models.User;
import com.gti619.spring.login.payload.response.UserInfoResponse;
import com.gti619.spring.login.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class UserService {
    @Autowired
    private UserRepository userRepository;

    public List<UserInfoResponse> getAllUsers() {
        // Fetch all users
        List<User> users = userRepository.findAll();

        // Transform the list of User entities into UserInfoResponse DTOs
        List<UserInfoResponse> userInfos = users.stream().map(user -> {


            List<String> roles = user.getRoles().stream()
                    .map(role -> role.getName().name()) // Convert the ERole enum to a string
                    .collect(Collectors.toList());


            return new UserInfoResponse(
                    user.getId(),
                    user.getUsername(),
                    user.getEmail(),
                    roles
            );
        }).collect(Collectors.toList());

        return userInfos;
    }
}
