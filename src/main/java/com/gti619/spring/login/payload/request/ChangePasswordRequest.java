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

    private boolean blocked;

    private boolean disabled;

    public ChangePasswordRequest(Long userId, String userPassword, boolean blocked) {
        this.userId = userId;
        this.userPassword = userPassword;
        this.blocked = blocked;
    }



    public ChangePasswordRequest() {

    }
}