package com.gti619.spring.login.payload.response;

public class CheckValidResponse {

    private boolean valid;

    public boolean isBlocked() {
        return valid;
    }

    public void setValid(boolean valid) {
        this.valid = valid;
    }

    public CheckValidResponse(boolean valid) {
        this.valid = valid;
    }
}
