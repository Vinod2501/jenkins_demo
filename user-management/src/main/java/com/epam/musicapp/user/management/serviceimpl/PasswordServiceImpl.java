package com.epam.musicapp.user.management.serviceimpl;

import com.epam.musicapp.user.management.exception.NewPasswordMatchesOldException;
import com.epam.musicapp.user.management.exception.PasswordsDoNotMatchException;
import com.epam.musicapp.user.management.service.PasswordService;
import com.epam.musicapp.user.management.utility.AESUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import static com.epam.musicapp.user.management.constants.UserConstants.*;
import static com.epam.musicapp.user.management.constants.UserConstants.NEW_PASSWORD_AND_OLD_PASSWORD_SHOULD_NOT_BE_SAME;

@Service
@RequiredArgsConstructor
public class PasswordServiceImpl implements PasswordService {
    private final PasswordEncoder passwordEncoder;

    public String decryptPassword(String encryptedPassword) {
        return AESUtils.decrypt(encryptedPassword);
    }

    public String encodePassword(String password) {
        return passwordEncoder.encode(password);
    }
    public void validatePassword(String password) {
        if (password == null || password.trim().isEmpty() || password.length() < 8 || !password.matches(PASSWORD_PATTERN)) {
            throw new IllegalArgumentException(PASSWORD_VALIDATION);
        }
    }
    public void checkPasswordsMatch( String newPassword, String confirmNewPassword) {

        if (!newPassword.equals(confirmNewPassword)) {
            throw new PasswordsDoNotMatchException(NEW_PASSWORD_AND_CONFIRM_PASSWORD_DOES_NOT_MATCH);
        }
    }
    public void checkNewPasswordAndOldPasswordMatch( String newPassword , String oldPasswordHash){
        if (checkBcryptPassword(newPassword, oldPasswordHash)) {
            throw new NewPasswordMatchesOldException(NEW_PASSWORD_AND_OLD_PASSWORD_SHOULD_NOT_BE_SAME);
        }
    }

    public boolean checkBcryptPassword(String decryptedPassword, String hashedPassword) {
        return passwordEncoder.matches(decryptedPassword, hashedPassword);
    }

}
