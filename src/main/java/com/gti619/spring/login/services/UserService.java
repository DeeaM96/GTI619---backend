package com.gti619.spring.login.services;

import com.gti619.spring.login.models.User;
import com.gti619.spring.login.payload.response.UserInfoResponse;
import com.gti619.spring.login.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.List;
import java.util.Optional;
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

    public void updateTentatives(Long id) throws UsernameNotFoundException {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new UsernameNotFoundException("User Not Found with id: " + id));

        user.setTentatives(user.getTentatives()+1);

        userRepository.save(user);
    }

    public void updateLastLogin(Long userId) {
        User user = userRepository.findById(userId).orElseThrow(() -> new UsernameNotFoundException("User Not Found with id: " + userId));
        user.setLastLogin(new Date());
        userRepository.save(user);
    }

    public void handleFailedLogin(String username) {
        User user = userRepository.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException("User Not Found with username: " + username));
        Integer tentatives = user.getTentatives() == null ? 0 : user.getTentatives();
        user.setLoginAttempt(new Date());
        user.setTentatives(tentatives + 1);

        if (tentatives >= 5) {
            user.setBlocked(true);
        }

        userRepository.save(user);
    }

    public User findByUsername(String username) {
        return userRepository.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException("User Not Found with username: " + username));

    }


}
