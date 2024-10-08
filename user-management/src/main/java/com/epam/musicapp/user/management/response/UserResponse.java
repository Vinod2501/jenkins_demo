package com.epam.musicapp.user.management.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class UserResponse {
    private Long userId;
    private String message;
    private String verificationStatus;

    public UserResponse(String message) {
        this.message = message;
    }

    public UserResponse() {
    }
}
