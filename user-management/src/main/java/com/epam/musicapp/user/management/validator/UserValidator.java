package com.epam.musicapp.user.management.validator;

import com.epam.musicapp.user.management.exception.InvalidEmailException;
import com.epam.musicapp.user.management.exception.InvalidPasswordException;
import com.epam.musicapp.user.management.exception.InvalidUserNameException;
import com.epam.musicapp.user.management.request.UserRequest;

import org.springframework.stereotype.Component;

import static com.epam.musicapp.user.management.constants.UserConstants.*;

@Component
public class UserValidator {
    private UserValidator() {
    }

    public static void validate(UserRequest userRequest) {

        if (userRequest.getUserName() == null) {
            throw new InvalidUserNameException(NULL_USERNAME);
        }

        if (userRequest.getUserName().length() > 10 || userRequest.getUserName().length() < 5) {
            throw new InvalidUserNameException(USERNAME_LENGTH);
        }


        if (!userRequest.getUserName().matches(USERNAME_PATTERN)) {
            throw new InvalidUserNameException(INVALID_USERNAME);
        }

        if (userRequest.getPassword() == null) {
            throw new InvalidPasswordException(NULL_PASSWORD);
        }

        if (!userRequest.getPassword().matches(PASSWORD_PATTERN)) {
            throw new InvalidPasswordException(INVALID_PASSWORD);
        }

        if (userRequest.getUserEmail() == null) {
            throw new InvalidEmailException(NULL_EMAIL);
        }

        if (userRequest.getUserEmail().isEmpty()) {
            throw new InvalidEmailException(EMPTY_EMAIL);
        }

        if (!userRequest.getUserEmail().matches(EMAIL_PATTERN)) {
            throw new InvalidEmailException(INVALID_EMAIL_FORMAT);
        }
    }

}
