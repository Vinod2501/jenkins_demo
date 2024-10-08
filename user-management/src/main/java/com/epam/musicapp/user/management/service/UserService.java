package com.epam.musicapp.user.management.service;

import com.epam.musicapp.user.management.exception.InvalidCredentialsException;
import com.epam.musicapp.user.management.request.UserRequest;
import com.epam.musicapp.user.management.request.UserRequestV2;
import com.epam.musicapp.user.management.response.UserResponse;
import com.epam.musicapp.user.management.response.UserResponseV2;

public interface UserService {
    UserResponse verify(Long userId);
    UserResponse login(UserRequest loginRequest) throws InvalidCredentialsException;
    UserResponse verifyUser(String token);
    String changePasswordProcess(String username, String encryptedNewPassword, String encryptedConfirmPassword);
    void registerUser(UserRequest userRequest);
    UserResponseV2 signInProcess(UserRequestV2 userRequest);
    boolean isUserExists(String userName) ;
}
