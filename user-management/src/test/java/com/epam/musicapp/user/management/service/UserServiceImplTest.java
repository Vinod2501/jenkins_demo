package com.epam.musicapp.user.management.service;

import com.epam.musicapp.user.management.exception.*;
import com.epam.musicapp.user.management.response.UserResponse;
import com.epam.musicapp.user.management.entity.User;
import com.epam.musicapp.user.management.repository.UserRepository;
import com.epam.musicapp.user.management.serviceimpl.TokenServiceImpl;
import com.epam.musicapp.user.management.serviceimpl.UserServiceImpl;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import org.junit.jupiter.api.BeforeEach;
import com.epam.musicapp.user.management.request.UserRequest;
import com.epam.musicapp.user.management.request.UserRequestV2;
import com.epam.musicapp.user.management.response.UserResponseV2;
import com.epam.musicapp.user.management.utility.JwtUtil;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Date;
import java.util.List;
import java.util.Optional;
import static com.epam.musicapp.user.management.constants.UserConstants.USER_VERIFIED;
import static com.epam.musicapp.user.management.constants.UserConstants.VERIFICATION_REQUIRED;

import static com.epam.musicapp.user.management.constants.UserConstants.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

import org.mockito.Mockito;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserServiceImplTest {

    @InjectMocks
    private UserServiceImpl userService;

    @Mock
    private UserRepository userRepository;

    @Mock
    private JwtUtil jwtUtil;
    UserRequest userRequest = new UserRequest();

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private PasswordService passwordService;

    private User user;

    @InjectMocks
    private TokenServiceImpl tokenService;

    @BeforeEach
    void setUp() {
        user = User.builder()
                .userName("test")
                .userPassword(passwordEncoder.encode("oldPass"))
                .build();
    }

    @Test
    void testValidAndVerifiedUser() {
        when(userRepository.findById(1L)).thenReturn(Optional.of(new User(1L, "username", "password", "email", "verified")));

        UserResponse response = userService.verify(1L);

        assertEquals(1L, response.getUserId());
        assertEquals("verified", response.getVerificationStatus());
        assertEquals(USER_VERIFIED, response.getMessage());
    }

    @Test
    void testValidAndPendingUser() {
        when(userRepository.findById(1L)).thenReturn(Optional.of(new User(1L, "username", "password", "email", "pending")));

        UserResponse response = userService.verify(1L);

        assertEquals(1L, response.getUserId());
        assertEquals("pending", response.getVerificationStatus());
        assertEquals(VERIFICATION_REQUIRED, response.getMessage());
    }

    @Test
    void testNonExistingUserId() {
        when(userRepository.findById(100L)).thenReturn(Optional.empty());
        assertThrows(UserNotFoundException.class, () -> userService.verify(100L));
    }

    @Test
    void testNegativeUserId() {
        assertThrows(IllegalArgumentException.class, () -> userService.verify(-1L));
    }

    @Test
    void testZeroUserId() {
        assertThrows(IllegalArgumentException.class, () -> userService.verify(0L));
    }

    @Test
    void testLoginSuccessful() throws InvalidCredentialsException, ValidationException {
        String email = "user1@email.com";
        String password = "password1";
        UserRequest requestDTO = new UserRequest(email, password);
        User userEntity = new User();
        userEntity.setUserEmail(email);
        userEntity.setUserPassword(password);

        when(userRepository.findByUserEmail(email)).thenReturn(Optional.of(userEntity));
        UserResponse response = userService.login(requestDTO);

        assertEquals(LOGIN_SUCCESS, response.getMessage());
    }

    @Test
    void testLoginWithWrongCredentials() {
        UserRequest request = new UserRequest(EMAIL, PASSWORD);

        when(userRepository.findByUserEmail(EMAIL)).thenReturn(Optional.empty());

        assertThrows(InvalidCredentialsException.class, () -> userService.login(request));
    }

    @Test
    void testLoginWithIncorrectPassword() {
        UserRequest requestDTO = new UserRequest(EMAIL, "wrongPassword");
        when(userRepository.findByUserEmail(EMAIL)).thenReturn(Optional.of(new User(1L, "username", PASSWORD, EMAIL, "verified")));

        assertThrows(InvalidCredentialsException.class, () -> userService.login(requestDTO));
    }



    @Test
     void testRegisterUser_UserAlreadyExists() {
        userRequest.setUserName("Rohit");
        userRequest.setUserEmail("rohit@gmail.com");
        userRequest.setPassword("Rohit@123");

        when(userRepository.existsByUserName(userRequest.getUserName())).thenReturn(true);

        assertThrows(UserAlreadyExistsException.class, () -> userService.registerUser(userRequest));
    }

    @Test
     void testRegisterUser_WhenUserNameIsInvalid() {
        userRequest.setUserName("Rohit#@");  // Invalid username
        userRequest.setUserEmail("rohit@gmail.com");
        userRequest.setPassword("Rohit@123");

        assertThrows(InvalidUserNameException.class, () -> userService.registerUser(userRequest));
    }

    @Test
     void testRegisterUser_WhenUserNameIsNull() {
        userRequest.setUserName(null);
        userRequest.setUserEmail("rohit@gmail.com");
        userRequest.setPassword("Rohit@123");

        assertThrows(InvalidUserNameException.class, () -> userService.registerUser(userRequest));
    }

    @Test
     void testRegisterUser_WhenUserNameIsEmpty() {
        userRequest.setUserName(" ");
        userRequest.setUserEmail("rohit@gmail.com");
        userRequest.setPassword("Rohit@123");

        assertThrows(InvalidUserNameException.class, () -> userService.registerUser(userRequest));
    }

    @Test
     void testRegisterUser_LengthOfUserNameIsGreaterThan10() {
        userRequest.setUserName("rohitkkumar");
        userRequest.setUserEmail("rohit@gmail.com");
        userRequest.setPassword("Rohit@123");

        assertThrows(InvalidUserNameException.class, () -> userService.registerUser(userRequest));
    }

    @Test
     void testRegisterUser_WhenUserEmailIsInvalid() {
        userRequest.setUserName("Rohit");
        userRequest.setUserEmail("rohitgmail.com"); // Invalid email
        userRequest.setPassword("Rohit@123");

        assertThrows(InvalidEmailException.class, () -> userService.registerUser(userRequest));
    }

    @Test
     void testRegisterUser_WhenUserEmailIsNull() {
        userRequest.setUserName("Rohit");
        userRequest.setUserEmail(null);
        userRequest.setPassword("Rohit@123");

        assertThrows(InvalidEmailException.class, () -> userService.registerUser(userRequest));
    }

    @Test
     void testRegisterUser_WhenUserEmailIsEmpty() {
        userRequest.setUserName("Rohit");
        userRequest.setUserEmail(" ");
        userRequest.setPassword("Rohit@123");

        assertThrows(InvalidEmailException.class, () -> userService.registerUser(userRequest));
    }

    @Test
     void testRegisterUser_WhenPasswordIsNull() {
        userRequest.setUserName("Rohit");
        userRequest.setUserEmail("rohit@gmail.com");
        userRequest.setPassword(null);

        assertThrows(InvalidPasswordException.class, () -> userService.registerUser(userRequest));
    }

    @Test
     void testRegisterUser_WhenPasswordIsEmpty() {
        userRequest.setUserName("Rohit");
        userRequest.setUserEmail("rohit@gmail.com");
        userRequest.setPassword(" ");

        assertThrows(InvalidPasswordException.class, () -> userService.registerUser(userRequest));
    }

    @Test
    void testRegisterUser_WhenPasswordIsInvalid() {
        userRequest.setUserName("Rohit");
        userRequest.setUserEmail("rohit@gmail.com");
        userRequest.setPassword("Rohit123"); // Invalid password

        assertThrows(InvalidPasswordException.class, () -> userService.registerUser(userRequest));
    }

    @Test
     void testRegisterUser_WhenPasswordLengthIsLessThan8() {
        userRequest.setUserName("Rohit");
        userRequest.setUserEmail("rohit@gmail.com");
        userRequest.setPassword("Rohit@1"); // Invalid password

        assertThrows(InvalidPasswordException.class, () -> userService.registerUser(userRequest));
    }
    @Test
    void testWhenValidUserAndPasswordThenShouldUpdatePassword() {
        when(userRepository.findByUserName(user.getUserName())).thenReturn(Optional.of(user));
        String result = userService.changePasswordProcess("test", "U2FsdGVkX1+5RCVY23k71krZJgqIB8YUjVIPMBNMh0Q=", "U2FsdGVkX1+5RCVY23k71krZJgqIB8YUjVIPMBNMh0Q=");
        assertEquals("Password is updated successfully.", result);
    }
    @Test
    void testWhenNewPasswordAndConfirmPasswordDoNotMatchThenShouldThrowException() {
        doThrow(new PasswordsDoNotMatchException(NEW_PASSWORD_AND_CONFIRM_PASSWORD_DOES_NOT_MATCH)).when(passwordService).checkPasswordsMatch("U2FsdGVkX1+5RCVY23k71krZJgqIB8YUjVIPMBNMh0Q=", "mD6bA33SlAJjHGoIMU/S8Q==");
        assertThrows(PasswordsDoNotMatchException.class, () ->
                userService.changePasswordProcess("test", "U2FsdGVkX1+5RCVY23k71krZJgqIB8YUjVIPMBNMh0Q=", "mD6bA33SlAJjHGoIMU/S8Q=="));
    }
    @Test
    void testWhenUserNotFoundThenShouldThrowException() {
        when(userRepository.findByUserName(user.getUserName())).thenReturn(Optional.empty());
        assertThrows(UserNotFoundException.class, () -> userService.changePasswordProcess("test", "U2FsdGVkX1+5RCVY23k71krZJgqIB8YUjVIPMBNMh0Q=", "U2FsdGVkX1+5RCVY23k71krZJgqIB8YUjVIPMBNMh0Q="));
    }
    @Test
    void testInvalidPassword() {
        String decryptedInvalidPassword = "short";
        when(passwordService.decryptPassword(Mockito.anyString())).thenReturn(decryptedInvalidPassword);
        doThrow(new IllegalArgumentException(PASSWORD_VALIDATION)).when(passwordService).validatePassword(decryptedInvalidPassword);
        assertThrows(IllegalArgumentException.class, () ->
                userService.changePasswordProcess("test", "encryptedInvalidPassword", "encryptedInvalidPassword"));
    }
    @Test
    void testInvalidPasswordPattern() {
        String decryptedInvalidPassword = "invalidPassword";
        when(passwordService.decryptPassword(Mockito.anyString())).thenReturn(decryptedInvalidPassword);
        doThrow(new IllegalArgumentException(PASSWORD_VALIDATION)).when(passwordService).validatePassword(decryptedInvalidPassword);
        assertThrows(IllegalArgumentException.class, () ->
                userService.changePasswordProcess("test", "encryptedInvalidPassword", "encryptedInvalidPassword"));
    }
    @Test
    void testEmptyPassword() {
        String decryptedEmptyPassword = "";
        when(passwordService.decryptPassword(Mockito.anyString())).thenReturn(decryptedEmptyPassword);
        doThrow(new IllegalArgumentException(PASSWORD_VALIDATION)).when(passwordService).validatePassword(decryptedEmptyPassword);
        assertThrows(IllegalArgumentException.class, () ->
                userService.changePasswordProcess("test", "encryptedEmptyPassword", "encryptedEmptyPassword"));
    }
    @Test
    void testNewPasswordIsSameAsOldPassword() {
        String decryptedPassword = "oldPass";
        when(userRepository.findByUserName(user.getUserName())).thenReturn(Optional.of(user));
        when(passwordService.decryptPassword(Mockito.any())).thenReturn(decryptedPassword);
        doThrow(new NewPasswordMatchesOldException(NEW_PASSWORD_AND_OLD_PASSWORD_SHOULD_NOT_BE_SAME))
                .when(passwordService).checkNewPasswordAndOldPasswordMatch(Mockito.anyString(), Mockito.nullable(String.class));
        assertThrows(NewPasswordMatchesOldException.class, () -> userService.changePasswordProcess("test", "encryptedPassword", "encryptedPassword"));
    }


    @Test
    void signIn_InvalidUsername_ThrowsAuthenticationFailedException() {
        String username = "invaliduser";
        String password = "password123";
        UserRequestV2 request = new UserRequestV2(username, password);
        when(userService.findByUserName(username)).thenReturn(Optional.empty());
        assertThrows(AuthenticationFailedException.class, () -> userService.signInProcess(request));
    }

    @Test
    void signIn_InvalidPassword_ThrowsAuthenticationFailedException() {
        String username = "testuser";
        String password = "invalidpassword";
        UserRequestV2 request = new UserRequestV2(username, password);
        User user = new User(1L, username, "test@example.com", "password123", "VERIFIED");
        when(userService.findByUserName(username)).thenReturn(Optional.of(user));
        assertThrows(AuthenticationFailedException.class, () -> userService.signInProcess(request));
    }

    @Test
    void signIn_NullUsername_ThrowsAuthenticationFailedException() {
        String password = "password123";
        UserRequestV2 request = new UserRequestV2(null, password);
        assertThrows(AuthenticationFailedException.class, () -> userService.signInProcess(request));
    }

    @Test
    void signIn_NullPassword_ThrowsAuthenticationFailedException() {
        String username = "testuser";
        UserRequestV2 request = new UserRequestV2(username, null);
        assertThrows(AuthenticationFailedException.class, () -> userService.signInProcess(request));
    }

    @Test
    void signIn_ValidCredentials_ReturnsUserResponse() {
        // Arrange
        String username = "testuser";
        String password = "Cu03NlaRL4SYh/na/UHb5g==";

        UserRequestV2 request = new UserRequestV2(username, password);
        User user = new User(1L, username, "test@example.com", "$2a$12$N0cwvJN97L6/0imLqoGb4.niZ/a/E8ce0KugCp9WTC77pFHczXl8a", "verified");

        when(userService.findByUserName(username)).thenReturn(Optional.of(user));
        when(userRepository.save(any(User.class))).thenReturn(user);
        when(jwtUtil.generateTokenUsingUserDetails(username,user.getUserId())).thenReturn("sample.token.value");

        // Act
        UserResponseV2 response = userService.signInProcess(request);

        // Assert
        assertEquals(username, response.getUsername());
        assertEquals(user.getUserEmail(), response.getEmail());
        assertNotNull(response.getToken());
    }

    @Test
    void testsSignIn_whenPasswordIsInvalid_thenAuthenticationFailedException() {
        // Arrange
        String username = "testuser";
        String password = "Cu03NlaRL4SYh/na/UHb5g==";

        UserRequestV2 request = new UserRequestV2(username, password);
        User user = new User(1L, username, "test@example.com", "$2a$12$N0cwvJN97L6/0imLqoGb4.niZ/a/E8ce0KugCp9WTC77pFHczXl8b", "verified");

        when(userService.findByUserName(username)).thenReturn(Optional.of(user));

        Exception ex = assertThrows(AuthenticationFailedException.class, () -> userService.signInProcess(request));
        assertEquals("Invalid username or password.", ex.getMessage());
    }


    @Test
     void testCheckTokenExpiration_ExpiredToken() {
        Claims claims = mock(Claims.class);
        when(claims.getExpiration()).thenReturn(new Date(System.currentTimeMillis() - 10000));

        assertThrows(JwtException.class, () -> tokenService.checkTokenExpiration(claims), TOKEN_EXPIRED);
    }

    @Test
     void testCheckTokenExpiration_ValidToken() {
        Claims claims = mock(Claims.class);
        when(claims.getExpiration()).thenReturn(new Date(System.currentTimeMillis() + 10000));

        assertDoesNotThrow(() -> tokenService.checkTokenExpiration(claims));
    }

    @Test
     void testExtractTokenContent_ValidClaims() {
        Claims claims = mock(Claims.class);
        when(claims.get(USERNAME, String.class)).thenReturn("username");
        when(claims.get(USER_ID, Long.class)).thenReturn(1L);

        List<Object> result = tokenService.extractTokenContent(claims);

        assertEquals("username", result.get(0));
        assertEquals(1L, result.get(1));
    }

    @Test
     void testExtractTokenContent_InvalidClaims() {
        Claims claims = mock(Claims.class);
        when(claims.get(USERNAME, String.class)).thenReturn(null);
        when(claims.get(USER_ID, Long.class)).thenReturn(null);

        assertThrows(JwtException.class, () -> tokenService.extractTokenContent(claims), INVALID_TOKEN_SIGNATURE);
    }
}