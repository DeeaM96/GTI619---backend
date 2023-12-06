package com.gti619.spring.login.payload.response;

public class UserBlockedResponse {

    private boolean blocked;

    public UserBlockedResponse(boolean blocked) {
        this.blocked = blocked;
    }

    public boolean isBlocked() {
        return blocked;
    }

    public void setBlocked(boolean blocked) {
        this.blocked = blocked;
    }
}
