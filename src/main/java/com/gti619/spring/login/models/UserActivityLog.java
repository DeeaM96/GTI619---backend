package com.gti619.spring.login.models;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;


import java.util.Date;

@Entity
@Getter
@Setter
@Table(name = "user_activity_log")
public class UserActivityLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_id")
    private Long userId;

    @Column(name = "activity_type")
    private String activityType; // e.g., "LOGIN" or "PASSWORD_CHANGE"

    @Column(name = "timestamp")
    private Date timestamp;

    @Column(name = "success")
    private boolean success;

    @Column(name = "error_message")
    private String errorMessage;


    // Constructors, getters, and setters
}
