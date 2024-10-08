package com.epam.musicapp.user.management.request;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import static com.epam.musicapp.user.management.constants.UserConstants.EMAIL_IS_MANDATORY;
import static com.epam.musicapp.user.management.constants.UserConstants.PASSWORD_IS_MANDATORY;


@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserRequest {

    private String userName;

    @NotBlank(message = EMAIL_IS_MANDATORY)
    private String userEmail;

    @NotBlank(message = PASSWORD_IS_MANDATORY)
    private String password;

    public UserRequest(String email, String password) {
        this.userEmail = email;
        this.password = password;
    }

}
