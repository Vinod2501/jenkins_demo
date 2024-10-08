package com.epam.musicapp.user.management.exception;

import com.epam.musicapp.user.management.response.UserResponse;
import lombok.Getter;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@Getter
@ResponseStatus(HttpStatus.BAD_REQUEST)
public class BadRequestException extends RuntimeException {

    private final UserResponse errorResponse;

    public BadRequestException(Long userId, String verificationStatus, String message) {
        super(message);
        this.errorResponse = new UserResponse(userId, verificationStatus, message);
    }

}