package com.gti619.spring.login.controllers;

import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import com.gti619.spring.login.payload.request.ChangePasswordRequest;
import com.gti619.spring.login.payload.request.UpdateRoleRequest;
import com.gti619.spring.login.payload.request.LoginRequest;
import com.gti619.spring.login.payload.request.SignupRequest;
import com.gti619.spring.login.payload.response.MessageResponse;
import com.gti619.spring.login.payload.response.UserBlockedResponse;
import com.gti619.spring.login.payload.response.UserInfoResponse;
import com.gti619.spring.login.security.jwt.JwtUtils;
import com.gti619.spring.login.security.services.UserDetailsServiceImpl;
import com.gti619.spring.login.services.UserService;
import jakarta.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.gti619.spring.login.models.ERole;
import com.gti619.spring.login.models.Role;
import com.gti619.spring.login.models.User;
import com.gti619.spring.login.repository.RoleRepository;
import com.gti619.spring.login.repository.UserRepository;
import com.gti619.spring.login.security.services.UserDetailsImpl;

//for Angular Client (withCredentials)
@CrossOrigin(origins = "http://localhost:4200,http://localhost:4200", maxAge = 3600, allowCredentials = "true")
//@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {
    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    JwtUtils jwtUtils;

    @Autowired
    UserService userService;

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        try {
            Authentication authentication = authenticationManager
                    .authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

            SecurityContextHolder.getContext().setAuthentication(authentication);

            UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

            User user = userService.findByUsername(userDetails.getUsername());


            ResponseCookie jwtCookie = jwtUtils.generateJwtCookie(userDetails);

            List<String> roles = userDetails.getAuthorities().stream()
                    .map(item -> item.getAuthority())
                    .collect(Collectors.toList());

            userService.updateLastLogin(userDetails.getId());


            if (user.getBlocked()) {
                return ResponseEntity
                        .status(HttpStatus.FORBIDDEN).header(HttpHeaders.SET_COOKIE, jwtCookie.toString())
                        .body(new UserInfoResponse(userDetails.getId(),
                                userDetails.getUsername(),

                                userDetails.isBlocked()

                        ));
            }


            return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, jwtCookie.toString())
                    .body(new UserInfoResponse(userDetails.getId(),
                            userDetails.getUsername(),
                            userDetails.getEmail(),
                            roles,
                            userDetails.isBlocked(),
                            userDetails.getLastLogin(),
                            userDetails.getLoginAttempt(),
                            userDetails.getTentatives()
                    ));

        } catch (BadCredentialsException e) {
            // Handle failed login attempt
            userService.handleFailedLogin(loginRequest.getUsername());
            throw e;
        }
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Username is already taken!"));
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Email is already in use!"));
        }

        // Create new user's account
        User user = new User(signUpRequest.getUsername(),
                signUpRequest.getEmail(),
                encoder.encode(signUpRequest.getPassword()));

        Set<String> strRoles = signUpRequest.getRole();
        Set<Role> roles = new HashSet<>();

        if (strRoles == null) {
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(adminRole);

                        break;
                    case "prep_aff":
                        Role role_prep_aff = roleRepository.findByName(ERole.ROLE_PREP_AFF)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(role_prep_aff);

                        break;
                    case "prep_res":
                        Role role_prep_red = roleRepository.findByName(ERole.ROLE_PREP_RES)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(role_prep_red);

                        break;
                    default:
                        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(userRole);
                }
            });
        }

        user.setRoles(roles);
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }

    @PostMapping("/createUser")
    @PreAuthorize("hasRole('ROLE_ADMIN') ")
    public ResponseEntity<?> createUser(@Valid @RequestBody SignupRequest signUpRequest) {
        String validationMessage = validatePassword(signUpRequest.getPassword());
        if (!validationMessage.equals("Valid")) {
            return ResponseEntity.badRequest().body(new MessageResponse(validationMessage));
        }
        return this.registerUser(signUpRequest);
    }


    @PostMapping("/signout")
    public ResponseEntity<?> logoutUser() {
        ResponseCookie cookie = jwtUtils.getCleanJwtCookie();
        return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, cookie.toString())
                .body(new MessageResponse("You've been signed out!"));
    }


    @PostMapping("/updateRole")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public ResponseEntity<?> updateRole(@Valid @RequestBody UpdateRoleRequest updateRoleRequest) {
        User user = userRepository.findByUsername(updateRoleRequest.getUsername())
                .orElseThrow(() -> new RuntimeException("Error: User is not found."));

        // Clear existing roles
        user.getRoles().clear();

        // Add new roles
        Set<Role> updatedRoles = new HashSet<>();

        Set<String> strRoles = updateRoleRequest.getNewRoles();
        if (strRoles == null) {
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            updatedRoles.add(userRole);
        } else {
            updateRoleRequest.getNewRoles().forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        updatedRoles.add(adminRole);
                        break;
                    case "prep_aff":
                        Role role_prep_aff = roleRepository.findByName(ERole.ROLE_PREP_AFF)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        updatedRoles.add(role_prep_aff);
                        break;
                    case "prep_res":
                        Role role_prep_red = roleRepository.findByName(ERole.ROLE_PREP_RES)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        updatedRoles.add(role_prep_red);
                        break;

                }
            });
        }


        user.setRoles(updatedRoles);
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("User roles updated successfully!"));
    }


    @PostMapping("/change-password")
    public ResponseEntity<?> changeUserPassword(@RequestBody ChangePasswordRequest changePasswordRequest) {
        try {
            User user = userRepository.findById(changePasswordRequest.getUserId())
                    .orElseThrow(() -> new UsernameNotFoundException("User Not Found with id: " + changePasswordRequest.getUserId()));

            String validationMessage = validatePassword(changePasswordRequest.getUserPassword());
            if (!validationMessage.equals("Valid")) {
                return ResponseEntity.badRequest().body(new MessageResponse(validationMessage));
            }

            user.setPassword(encoder.encode(changePasswordRequest.getUserPassword()));
            user.setBlocked(changePasswordRequest.isBlocked());
            userRepository.save(user);

            return ResponseEntity.ok(new MessageResponse("Password changed successfully!"));
        } catch (UsernameNotFoundException e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.NOT_FOUND);
        }
    }

    private String validatePassword(String password) {
        if (password.length() < 6) {
            return "Le mot de passe doit contenir au moins 6 caractères.";
        }
        if (!password.matches(".*[A-Z].*")) {
            return "Le mot de passe doit contenir au moins un caractère majuscule.";
        }
        if (!password.matches(".*[a-z].*")) {
            return "Le mot de passe doit contenir au moins un caractère minuscule.";
        }
        if (!password.matches(".*[0-9].*")) {
            return "Le mot de passe doit contenir au moins un chiffre.";
        }
        if (!password.matches(".*[!@#$%^&*(),.?\":{}|<>].*")) {
            return "Le mot de passe doit contenir au moins un caractère spécial.";
        }
        return "Valid";
    }

}
