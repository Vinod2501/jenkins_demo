package com.epam.musicapp.user.management.serviceimpl;

import com.epam.musicapp.user.management.constants.UserConstants;
import com.epam.musicapp.user.management.entity.User;
import com.epam.musicapp.user.management.exception.*;
import com.epam.musicapp.user.management.mapper.UserMapper;
import com.epam.musicapp.user.management.repository.UserRepository;
import com.epam.musicapp.user.management.request.UserRequest;
import com.epam.musicapp.user.management.request.UserRequestV2;
import com.epam.musicapp.user.management.response.UserResponse;
import com.epam.musicapp.user.management.response.UserResponseV2;
import com.epam.musicapp.user.management.service.EmailService;
import com.epam.musicapp.user.management.exception.InvalidCredentialsException;
import com.epam.musicapp.user.management.exception.BadRequestException;
import com.epam.musicapp.user.management.exception.UserNotFoundException;
import com.epam.musicapp.user.management.service.PasswordService;
import com.epam.musicapp.user.management.service.UserService;
import com.epam.musicapp.user.management.utility.AESUtils;
import com.epam.musicapp.user.management.utility.JwtUtil;
import com.epam.musicapp.user.management.validator.UserValidator;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCrypt;
import com.epam.musicapp.user.management.exception.UserAlreadyExistsException;
import jakarta.validation.constraints.NotNull;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;

import static com.epam.musicapp.user.management.constants.UserConstants.*;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final UserMapper userMapper;
    private final EmailService emailService;
    private final PasswordService passwordService;
    private final JwtUtil jwtUtil;


    @Override
    public String changePasswordProcess(String username, String encryptedNewPassword, String encryptedConfirmPassword) {
        passwordService.checkPasswordsMatch(encryptedNewPassword, encryptedConfirmPassword);
        String newPassword = passwordService.decryptPassword(encryptedNewPassword);
        passwordService.validatePassword(newPassword);
        User user = findByUserName(username)
                .orElseThrow(() -> new UserNotFoundException(USER_NOT_FOUND));
        passwordService.checkNewPasswordAndOldPasswordMatch(newPassword , user.getUserPassword());
        user.setUserPassword(passwordService.encodePassword(newPassword));
        saveUser(user);
        return PASSWORD_UPDATED_SUCCESSFULLY;
    }

    public Optional<User> findByUserName(String username) {
        return userRepository.findByUserName(username);
    }

    public void saveUser(@NotNull User user) {
        userRepository.save(user);
    }

    @Override
    public UserResponse verify(Long userId) {
        if (userId <= 0) {
            throw new IllegalArgumentException(INVALID_USER_ID);
        }
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException(USER_NOT_FOUND));

        UserResponse userResponse = new UserResponse();
        userResponse.setUserId(userId);
        userResponse.setVerificationStatus(user.getVerificationStatus());

        if (user.getVerificationStatus().equalsIgnoreCase(VERIFIED)) {
            userResponse.setMessage(USER_VERIFIED);
        } else {
            userResponse.setMessage(VERIFICATION_REQUIRED);
        }

        return userResponse;
    }

    @Override
    public UserResponse login(UserRequest loginRequest) throws InvalidCredentialsException {
        Optional<User> userInfo = userRepository.findByUserEmail(loginRequest.getUserEmail());
        User user = userInfo.orElseThrow(() -> new InvalidCredentialsException(INVALID_CREDENTIALS));

        if (!loginRequest.getPassword().equals(user.getUserPassword())) {
            throw new InvalidCredentialsException(INVALID_CREDENTIALS);
        }

        return new UserResponse(LOGIN_SUCCESS);
    }

    @Override
    public UserResponse verifyUser(String token) {
        String mailId = jwtUtil.extractEmail(token);
        Optional<User> optionalUser = userRepository.findByUserEmail(mailId);

        if (optionalUser.isEmpty()) {
            throw new UserNotFoundException(USER_NOT_FOUND);
        }

        User user = optionalUser.get();

        if (jwtUtil.validateToken(token)) {
            emailService.sendVerificationEmail(user);
            return new UserResponse(user.getUserId(), PENDING,
                    "Session expired. New verification email sent");
        }

        if (!PENDING.equalsIgnoreCase(user.getVerificationStatus())) {
            throw new BadRequestException(user.getUserId(), user.getVerificationStatus(), EMAIL_VERIFICATION_UNSUCCESSFUL);
        }

        user.setVerificationStatus(VERIFIED);
        String userName = user.getUserName();
        AuditorAwareImpl.setAuditor(userName);
        userRepository.save(user);

        return new UserResponse(user.getUserId(), user.getVerificationStatus(), EMAIL_VERIFICATION_SUCCESSFUL);
    }
    @Override
    public void registerUser(UserRequest userRequest) {
        UserValidator.validate(userRequest);
        validateIsUserExist(userRequest);

        User user = getUser(userRequest);
        userRepository.save(user);
        emailService.sendVerificationEmail(user);
    }

    private User getUser(UserRequest userRequest) {
        User user = userMapper.mapUserRequestToEntity(userRequest);
        user.setUserPassword(passwordService.encodePassword(user.getUserPassword()));
        user.setVerificationStatus(PENDING);
        user.setCreatedBy(userRequest.getUserName());
        return user;
    }

    private void validateIsUserExist(UserRequest userRequest) {
        if(userRepository.existsByUserName(userRequest.getUserName()) || userRepository.existsByUserEmail(userRequest.getUserEmail())) {
            throw new UserAlreadyExistsException(USER_ALREADY_EXISTS);
        }
    }

    private boolean checkPassword(String rawPassword, String encodedPassword) {
        return BCrypt.checkpw(rawPassword, encodedPassword);
    }

    public String decryptPassword(String encryptedPassword) {
        return AESUtils.decrypt(encryptedPassword);
    }

    @Override
    public UserResponseV2 signInProcess(UserRequestV2 request) {
        String username = request.getUsername();
        String password = request.getPassword();

        User user = findByUserName(username)
                .orElseThrow(() -> new AuthenticationFailedException(UserConstants.INVALID_CREDENTIALS_ERROR));

        checkAuthentication(user, password);

        final String token = generateToken(user);
        return new UserResponseV2(user.getUserName(), user.getUserEmail(), token);
    }

    private String generateToken(User user) {
        String token = jwtUtil.generateTokenUsingUserDetails(user.getUserName(), user.getUserId());
        user.setToken(token);
        user.setTokenIssuedAt(LocalDateTime.now());
        userRepository.save(user);
        return token;
    }

    public void checkAuthentication(User user, String encryptedPassword) {
        if (!user.getVerificationStatus().equals(UserConstants.VERIFIED)) {
            throw new AuthenticationFailedException(UserConstants.VERIFICATION_STATUS_MUST_BE_VERIFIED);
        }

        if (!checkPassword(decryptPassword(encryptedPassword), user.getUserPassword())) {
            throw new AuthenticationFailedException(UserConstants.INVALID_CREDENTIALS_ERROR);
        }
    }

    @Override
    public boolean isUserExists(String userName) {
        if (!userRepository.existsByUserName(userName)) {
           return false;
        }
        return true;
    }

}