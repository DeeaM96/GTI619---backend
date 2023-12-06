package com.gti619.spring.login.payload.request;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;

@Data
@Setter
@Getter
public class CheckValidRequest {
    private Long userId;

    public CheckValidRequest(Long userId) {
        this.userId = userId;
    }
}
