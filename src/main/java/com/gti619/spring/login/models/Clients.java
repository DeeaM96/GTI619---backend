package com.gti619.spring.login.models;

import jakarta.persistence.*;

import lombok.Getter;
import lombok.Setter;



@Entity
@Table(name="clients")
@Getter
@Setter
public class Clients {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Long id;

    @Column(name = "nom")
    private String nom;

    @Column(name = "prenom")
    private String prenom;

    @Column(name = "type")
    private int type;

    @Transient // This annotation makes sure that this field is not persisted in the database
    public String getTypeName() {
        switch (this.type) {
            case 1:
                return "RESIDENTIAL";
            case 2:
                return "AFFAIRE";
            default:
                return "UNKNOWN";
        }
    }
}
