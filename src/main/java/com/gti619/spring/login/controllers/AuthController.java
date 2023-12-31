package com.gti619.spring.login.controllers;

import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import com.gti619.spring.login.models.PasswordHistory;
import com.gti619.spring.login.payload.request.*;
import com.gti619.spring.login.payload.response.CheckValidResponse;
import com.gti619.spring.login.payload.response.MessageResponse;
import com.gti619.spring.login.payload.response.UserBlockedResponse;
import com.gti619.spring.login.payload.response.UserInfoResponse;
import com.gti619.spring.login.repository.PasswordHistoryRepository;
import com.gti619.spring.login.security.jwt.JwtUtils;
import com.gti619.spring.login.security.services.UserDetailsServiceImpl;
import com.gti619.spring.login.services.SecurityConfigService;
import com.gti619.spring.login.services.UserActivityService;
import com.gti619.spring.login.services.UserService;
import jakarta.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
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
import org.springframework.web.bind.annotation.*;

import com.gti619.spring.login.models.ERole;
import com.gti619.spring.login.models.Role;
import com.gti619.spring.login.models.User;
import com.gti619.spring.login.repository.RoleRepository;
import com.gti619.spring.login.repository.UserRepository;
import com.gti619.spring.login.security.services.UserDetailsImpl;

//for Angular Client (withCredentials)
@CrossOrigin(origins = {"http://localhost:4200", "https://localhost:4200"}, maxAge = 3600, allowCredentials = "true")
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
    PasswordHistoryRepository passwordHistoryRepository;

    @Autowired
    UserActivityService userActivityService;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    JwtUtils jwtUtils;

    @Autowired
    UserService userService;

    @Autowired
    SecurityConfigService securityConfigService;

   @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        try {
            Authentication authentication = authenticationManager
                    .authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

            SecurityContextHolder.getContext().setAuthentication(authentication);

            UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

            User user = userService.findByUsername(userDetails.getUsername());
            String intervalConfig = securityConfigService.getConfigValue("LOGIN_ENTRY_INTERVAL");
            long waitTime = intervalConfig != null ? Long.parseLong(intervalConfig) : 5 * 60 * 1000; // Utilisez la valeur par défaut si non configurée

            if (user.getLoginAttempt() != null) {
                long timeSinceLastAttempt = new Date().getTime() - user.getLoginAttempt().getTime();
                if (timeSinceLastAttempt < waitTime) {
                    long remainingTime = waitTime - timeSinceLastAttempt;
                    String errorMessage = "Tentative de connexion bloquée. Veuillez réessayer après " + remainingTime / 1000 + " secondes.";
                    userActivityService.logUserActivity(user.getId(), "LOGIN", false, errorMessage);

                    return ResponseEntity
                            .status(HttpStatus.TOO_MANY_REQUESTS)
                            .body(errorMessage);
                }
            }

            if(user.isDisabled()){
                String errorMessage="Tentative de connexion bloquée. Veuillez contacter un administrateur";
                userActivityService.logUserActivity(user.getId(), "LOGIN", false,errorMessage);

                return ResponseEntity
                        .status(HttpStatus.BAD_REQUEST)
                        .body(errorMessage);

            }

            ResponseCookie jwtCookie = jwtUtils.generateJwtCookie(userDetails);

            List<String> roles = userDetails.getAuthorities().stream()
                    .map(item -> item.getAuthority())
                    .collect(Collectors.toList());

            userService.updateLastLogin(userDetails.getId());


            if (user.getBlocked()) {
                userActivityService.logUserActivity(user.getId(), "LOGIN", false,"Utalisateur bloqué, veuillez changer votre mot de passe");

                return ResponseEntity
                        .status(HttpStatus.FORBIDDEN).header(HttpHeaders.SET_COOKIE, jwtCookie.toString())
                        .body(new UserInfoResponse(userDetails.getId(),
                                userDetails.getUsername(),

                                userDetails.isBlocked()

                        ));
            }

            user.setRelogin(false);

            userActivityService.logUserActivity(user.getId(), "LOGIN", true,null);



            return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, jwtCookie.toString())
                    .body(new UserInfoResponse(userDetails.getId(),
                            userDetails.getUsername(),
                            userDetails.getEmail(),
                            roles,
                            userDetails.isBlocked(),
                            userDetails.getLastLogin(),
                            userDetails.getLoginAttempt(),
                            userDetails.getTentatives(),
                            userDetails.isRelogin()
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
            return ResponseEntity.badRequest().body(new MessageResponse("Erreur: Nom d'utilisateur déjà utilisé!"));
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Erreur: Email déjà utilisé!"));
        }

        // Create new user's account
        User user = new User(signUpRequest.getUsername(),
                signUpRequest.getEmail(),
                encoder.encode(signUpRequest.getPassword()));

        user.setTentatives(0);

        Set<String> strRoles = signUpRequest.getRole();
        Set<Role> roles = new HashSet<>();

        if (strRoles == null) {
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Erreur: Rôle non trouvé."));
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Erreur: Rôle non trouvé."));
                        roles.add(adminRole);

                        break;
                    case "prep_aff":
                        Role role_prep_aff = roleRepository.findByName(ERole.ROLE_PREP_AFF)
                                .orElseThrow(() -> new RuntimeException("Erreur: Rôle non trouvé."));
                        roles.add(role_prep_aff);

                        break;
                    case "prep_res":
                        Role role_prep_red = roleRepository.findByName(ERole.ROLE_PREP_RES)
                                .orElseThrow(() -> new RuntimeException("Erreur: Rôle non trouvé."));
                        roles.add(role_prep_red);

                        break;
                    default:
                        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                                .orElseThrow(() -> new RuntimeException("Erreur: Rôle non trouvé."));
                        roles.add(userRole);
                }
            });
        }

        user.setRoles(roles);
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("Utilisateur enregistré avec succès!"));
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
                .body(new MessageResponse("Vous avez été déconnecté avec succès!"));
    }


    @PostMapping("/updateRole")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public ResponseEntity<?> updateRole(@Valid @RequestBody UpdateRoleRequest updateRoleRequest) {
        User user = userRepository.findByUsername(updateRoleRequest.getUsername())
                .orElseThrow(() -> new RuntimeException("Erreur: Rôle non trouvé."));

        // Supprimer les rôles existants
        user.getRoles().clear();

        // Ajouter les nouveaux rôles
        Set<Role> updatedRoles = new HashSet<>();

        Set<String> strRoles = updateRoleRequest.getNewRoles();
        if (strRoles == null) {
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Erreur: Rôle non trouvé."));
            updatedRoles.add(userRole);
        } else {
            updateRoleRequest.getNewRoles().forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Erreur: Rôle non trouvé."));
                        updatedRoles.add(adminRole);
                        break;
                    case "prep_aff":
                        Role role_prep_aff = roleRepository.findByName(ERole.ROLE_PREP_AFF)
                                .orElseThrow(() -> new RuntimeException("Erreur: Rôle non trouvé."));
                        updatedRoles.add(role_prep_aff);
                        break;
                    case "prep_res":
                        Role role_prep_red = roleRepository.findByName(ERole.ROLE_PREP_RES)
                                .orElseThrow(() -> new RuntimeException("Erreur: Rôle non trouvé."));
                        updatedRoles.add(role_prep_red);
                        break;

                }
            });
        }


        user.setRoles(updatedRoles);
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("Rôle(s) modifié(s) avec succès!"));
    }


    @GetMapping("/isValid")
    @PreAuthorize("hasRole('ROLE_USER') or hasRole('ROLE_PREP_RES') or hasRole('ROLE_ADMIN') or hasRole('ROLE_PREP_AFF')")
    public ResponseEntity<?> isValid() {


        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();


        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        User user = userRepository.findById(userDetails.getId())
                .orElseThrow(() -> new RuntimeException("Erreur: User non trouvé."));

        // Supprimer les rôles existants
        CheckValidResponse isValid= new CheckValidResponse(user.isRelogin());


        return ResponseEntity.ok(isValid);
    }


    @PostMapping("/change-password")
    @PreAuthorize("hasRole('ROLE_USER') or hasRole('ROLE_PREP_RES') or hasRole('ROLE_ADMIN') or hasRole('ROLE_PREP_AFF')")
    public ResponseEntity<?> changeUserPassword(@RequestBody ChangePasswordRequest changePasswordRequest) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        // Check if the user has the ADMIN role
        boolean isAdmin = authentication.getAuthorities().stream()
                .anyMatch(authority -> authority.getAuthority().equals("ROLE_ADMIN"));


        String activity_type=isAdmin? "ADMIN_PASSWORD_CHANGE" : "PASSWORD_CHANGE";


        try {
            User user = userRepository.findById(changePasswordRequest.getUserId())
                    .orElseThrow(() -> new UsernameNotFoundException("Utilisateur non trouvé avec le nom: " + changePasswordRequest.getUserId()));

            String reuseConfig = securityConfigService.getConfigValue("PASSWORD_REUSE_HISTORY");
            int reuseHistory = reuseConfig != null ? Integer.parseInt(reuseConfig) : 5; // Default to 5 if not configured

            Pageable topN = PageRequest.of(0, reuseHistory);
            List<PasswordHistory> lastPasswords = passwordHistoryRepository.findTopNByUserOrderByChangeDateDesc(user, topN);

            boolean isRepeated = lastPasswords.stream()
                    .anyMatch(history -> encoder.matches(changePasswordRequest.getUserPassword(), history.getPassword()));

            if (isRepeated) {
                String errorMessage = "Le nouveau mot de passe doit être différent des anciens " + reuseHistory + " passwords.";
                userActivityService.logUserActivity(user.getId(), "PASSWORD_CHANGE", false, errorMessage);

                return ResponseEntity.badRequest().body(errorMessage);
            }


            String validationMessage = validatePassword(changePasswordRequest.getUserPassword());
            if (!validationMessage.equals("Valid")) {
                userActivityService.logUserActivity(user.getId(), activity_type, false,validationMessage);

                return ResponseEntity.badRequest().body(new MessageResponse(validationMessage));
            }

            user.setPassword(encoder.encode(changePasswordRequest.getUserPassword()));
            user.setBlocked(changePasswordRequest.isBlocked());

            if(isAdmin){
                user.setBlocked(false);
                user.setDisabled(false);
                user.setTentatives(0);
                user.setRelogin(true);
            }
            userRepository.save(user);

            PasswordHistory newHistory = new PasswordHistory();
            newHistory.setUser(user);
            newHistory.setPassword(user.getPassword());
            newHistory.setChangeDate(new Date());
            passwordHistoryRepository.save(newHistory);

            userActivityService.logUserActivity(user.getId(), activity_type, true, null);

            return ResponseEntity.ok(new MessageResponse("Mot de passe modifié avec succès!"));
        } catch (UsernameNotFoundException e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.NOT_FOUND);
        }
    }

    private String validatePassword(String password) {
        String minLengthConfig = securityConfigService.getConfigValue("PASSWORD_MIN_LENGTH");
        int minLength = minLengthConfig != null ? Integer.parseInt(minLengthConfig) : 6; // Valeur par défaut

        if (password.length() < minLength) {
            return "Le mot de passe doit contenir au moins " + minLength + " caractères.";
        }

        if (Boolean.parseBoolean(securityConfigService.getConfigValue("PASSWORD_REQUIRE_UPPERCASE")) && !password.matches(".*[A-Z].*")) {
            return "Le mot de passe doit contenir au moins un caractère majuscule.";
        }

        if (Boolean.parseBoolean(securityConfigService.getConfigValue("PASSWORD_REQUIRE_LOWERCASE")) && !password.matches(".*[a-z].*")) {
            return "Le mot de passe doit contenir au moins un caractère minuscule.";
        }

        if (Boolean.parseBoolean(securityConfigService.getConfigValue("PASSWORD_REQUIRE_DIGITS")) && !password.matches(".*[0-9].*")) {
            return "Le mot de passe doit contenir au moins un chiffre.";
        }

        if (Boolean.parseBoolean(securityConfigService.getConfigValue("PASSWORD_REQUIRE_SPECIAL")) && !password.matches(".*[!@#$%^&*(),.?\":{}|<>].*")) {
            return "Le mot de passe doit contenir au moins un caractère spécial.";
        }
        return "Valid";
    }

}
