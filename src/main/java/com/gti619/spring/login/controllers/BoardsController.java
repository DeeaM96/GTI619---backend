package com.gti619.spring.login.controllers;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

//for Angular Client (withCredentials)
@CrossOrigin(origins = "http://localhost:4200", maxAge = 3600, allowCredentials="true")
//@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/test")
public class BoardsController {
  @GetMapping("/all")
  public String allAccess() {
    return "Contenu tous rôles";
  }

  @GetMapping("/user")
  @PreAuthorize("hasRole('ROLE_USER') or hasRole('ROLE_PREP_RES') or hasRole('ROLE_ADMIN') or hasRole('ROLE_PREP_AFF')")
  public String userAccess() {
    return "Contenu utilisateur";
  }

  @GetMapping("/prep_res")
  @PreAuthorize("hasRole('ROLE_PREP_RES') or hasRole('ROLE_ADMIN')  ")
  public String prep_res_access() {
    return "Tableau de bord ROLE_PREP_RES";
  }

  @GetMapping("/prep_aff")
  @PreAuthorize("hasRole('ROLE_PREP_AFF') or hasRole('ROLE_ADMIN') ")
  public String prep_aff_access() {
    return "Tableau de bord ROLE_PREP_AFF Board";
  }


  public String utilisateursBoard() {
    return "Liste Utilisateurs";
  }



  @GetMapping("/admin")
  @PreAuthorize("hasRole('ROLE_ADMIN')")
  public String adminAccess() {
    return "Tableau de bord administrateur";
  }


}
