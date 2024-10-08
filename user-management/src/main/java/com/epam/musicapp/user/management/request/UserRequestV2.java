package com.epam.musicapp.user.management.request;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class UserRequestV2 {

    @NotBlank(message = "Username must not be empty or null")
    private String username;

    @NotBlank(message = "Password must not be empty or null")
    private String password;
}

