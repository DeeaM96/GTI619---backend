package com.gti619.spring.login.services;

import com.gti619.spring.login.models.UserActivityLog;
import com.gti619.spring.login.repository.UserActivityLogRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
public class UserActivityService {

    @Autowired
    private UserActivityLogRepository userActivityLogRepository;

    // Existing methods...

    public void logUserActivity(Long userId, String activityType, boolean success, String errorMessage) {
        UserActivityLog logEntry = new UserActivityLog();
        logEntry.setUserId(userId);
        logEntry.setActivityType(activityType);
        logEntry.setTimestamp(new Date());
        logEntry.setSuccess(success);
        logEntry.setErrorMessage(errorMessage);
        userActivityLogRepository.save(logEntry);
    }
}
