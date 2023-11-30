package com.gti619.spring.login.payload.request;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;

@Data
@Setter
@Getter
public class ChangePasswordRequest {
    private Long userId;
    private String userPassword;

    public ChangePasswordRequest(Long userId, String userPassword) {
        this.userId = userId;
        this.userPassword = userPassword;
    }

    public ChangePasswordRequest() {

    }
}