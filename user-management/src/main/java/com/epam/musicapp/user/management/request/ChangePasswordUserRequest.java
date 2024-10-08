package com.epam.musicapp.user.management.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import static com.epam.musicapp.user.management.constants.UserConstants.*;


@Data
@NoArgsConstructor
@AllArgsConstructor
public class ChangePasswordUserRequest {

    @NotBlank(message = USER_NAME_CANNOT_BE_EMPTY)
    @NotNull(message = USER_NAME_CANNOT_BE_NULL)
    private String userName;

    @NotBlank(message = PASSWORD_CANNOT_BE_EMPTY)
    @NotNull(message = NULL_PASSWORD)
    private String newPassword;

    @NotBlank(message = PASSWORD_CANNOT_BE_EMPTY)
    @NotNull(message = NULL_PASSWORD)
    private String confirmNewPassword;
}
