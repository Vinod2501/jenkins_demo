package com.epam.musicapp.user.management.controller;

import com.epam.musicapp.user.management.constants.UserConstants;
import com.epam.musicapp.user.management.exception.*;
import com.epam.musicapp.user.management.request.ChangePasswordUserRequest;
import com.epam.musicapp.user.management.request.UserRequest;
import com.epam.musicapp.user.management.request.UserRequestV2;
import com.epam.musicapp.user.management.response.UserResponse;
import com.epam.musicapp.user.management.response.UserResponseV2;
import com.epam.musicapp.user.management.exception.UserNotFoundException;
import com.epam.musicapp.user.management.exception.BadRequestException;
import static com.epam.musicapp.user.management.constants.UserConstants.*;
import static com.epam.musicapp.user.management.utility.JwtUtil.asJsonString;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

import com.epam.musicapp.user.management.service.TokenService;
import com.epam.musicapp.user.management.service.UserService;
import com.epam.musicapp.user.management.exception.InvalidEmailException;
import com.epam.musicapp.user.management.exception.InvalidPasswordException;
import com.epam.musicapp.user.management.exception.InvalidUserNameException;
import com.epam.musicapp.user.management.exception.UserAlreadyExistsException;
import com.epam.musicapp.user.management.utility.JwtUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.JwtException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.springframework.web.bind.MissingServletRequestParameterException;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import static com.epam.musicapp.user.management.constants.UserConstants.EMAIL_VERIFICATION_SUCCESSFUL;
import static com.epam.musicapp.user.management.constants.UserConstants.VERIFIED;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;

@SpringBootTest
@AutoConfigureMockMvc
class UserControllerTest{

    @Autowired
    MockMvc mockMvc;

    @MockBean
    UserService userService;

    @Mock
    private TokenService tokenService;

    @InjectMocks
    private UserController userController;

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final JwtUtil jwtUtil = Mockito.mock(JwtUtil.class);
    String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdGFmZklkIjoiOTIifQ.dupIgphnK9Cnw_aBilks3p8jG_2s2alPhYThI1u2Qt0";

    Long userId;
    String mailId;
    MockHttpServletRequestBuilder requestBuilder;

    UserRequest userRequest = new UserRequest();
    ChangePasswordUserRequest changePasswordUserRequest = new ChangePasswordUserRequest();

    @Value("${app.tokens.validToken}")
    private String validToken;

    @Value("${app.tokens.invalidToken}")
    private String invalidToken;

    @Value("${app.tokens.expiredToken}")
    private String expiredToken;

    @BeforeEach
    void setup() {
        userId = 1L;
        mailId = UserConstants.EMAIL;
        requestBuilder = get("/user-management/users/verify")
                .param("userId", userId.toString())
                .param("mailId", mailId)
                .contentType(MediaType.APPLICATION_JSON);
    }

    @Test
    void testValidUserWithVerifiedStatus() throws Exception {
        UserResponse dto = new UserResponse();
        dto.setUserId(1L);
        dto.setVerificationStatus(VERIFIED);
        dto.setMessage(UserConstants.USER_VERIFIED);

        Mockito.when(userService.verify(1L)).thenReturn(dto);

        this.mockMvc.perform(MockMvcRequestBuilders.get("/user-management/users/is_verified/1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.userId").value(1L))
                .andExpect(jsonPath("$.message").value(UserConstants.USER_VERIFIED))
                .andExpect(jsonPath("$.verificationStatus").value(VERIFIED));
    }

    @Test
    void testValidUserAndPending() throws Exception {
        UserResponse dto = new UserResponse();
        dto.setUserId(1L);
        dto.setVerificationStatus(PENDING);
        dto.setMessage(VERIFICATION_REQUIRED);

        Mockito.when(userService.verify(1L)).thenReturn(dto);

        this.mockMvc.perform(MockMvcRequestBuilders.get("/user-management/users/is_verified/1"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.userId").value(1L))
                .andExpect(jsonPath("$.message").value(VERIFICATION_REQUIRED))
                .andExpect(jsonPath("$.verificationStatus").value(PENDING));
    }

    @Test
    void testInvalidUserId() throws Exception {
        when(userService.verify(0L)).thenThrow(new IllegalArgumentException(UserConstants.INVALID_USER_ID));
        mockMvc.perform(MockMvcRequestBuilders.get("/user-management/users/is_verified/{userId}", 0L))
                .andExpect(status().isBadRequest());
    }

    @Test
    void testInvalidUserIdNegative() throws Exception {
        when(userService.verify(-1L)).thenThrow(new IllegalArgumentException(UserConstants.INVALID_USER_ID));
        mockMvc.perform(MockMvcRequestBuilders.get("/user-management/users/is_verified/{userId}", -1L))
                .andExpect(status().isBadRequest());
    }

    @Test
    void testInvalidUserIdString() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.get("/user-management/users/is_verified/{userId}", "abc"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void testInvalidUserIdStringSpecialCharacters() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.get("/user-management/users/is_verified/{userId}", "a@b"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void testLogin_Success() throws Exception {
        // Mocking the service response
        UserResponse mockResponse = new UserResponse(UserConstants.LOGIN_SUCCESS);
        when(userService.login(any(UserRequest.class))).thenReturn(mockResponse);

        // Creating a request body
        UserRequest requestDTO = new UserRequest(UserConstants.EMAIL, UserConstants.PASSWORD);

        String requestBody = objectMapper.writeValueAsString(requestDTO);

         requestBuilder = post(UserConstants.LOGIN_ENDPOINT)
                .contentType(MediaType.APPLICATION_JSON)
                .content(requestBody);

        mockMvc.perform(requestBuilder)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value(UserConstants.LOGIN_SUCCESS));
    }

    @Test
    void testLogin_InvalidCredentials() throws Exception {
        // Mocking the service to throw InvalidCredentialsException
        when(userService.login(any(UserRequest.class)))
                .thenThrow(new InvalidCredentialsException(UserConstants.INVALID_CREDENTIALS));

        // Creating a request body with invalid credentials
        UserRequest requestDTO = new UserRequest(UserConstants.INVALID_EMAIL, UserConstants.WRONG_PASSWORD);

        // Using ObjectMapper to convert request to JSON string
        String requestBody = objectMapper.writeValueAsString(requestDTO);

        // Creating a request builder
         requestBuilder = post(UserConstants.LOGIN_ENDPOINT)
                .contentType(MediaType.APPLICATION_JSON)
                .content(requestBody);

        // Performing the request
        mockMvc.perform(requestBuilder)
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value(UserConstants.INVALID_CREDENTIALS));
    }

    @Test
    void testLogin_BadRequest() throws Exception {
        // Creating a request body with missing 'email' field
        UserRequest requestDTO = new UserRequest(null, UserConstants.PASSWORD);

        // Using ObjectMapper to convert request to JSON string
        String requestBody = objectMapper.writeValueAsString(requestDTO);

        // Creating a request builder
         requestBuilder = post(UserConstants.LOGIN_ENDPOINT)
                .contentType(MediaType.APPLICATION_JSON)
                .content(requestBody);

        // Performing the request and asserting the response
        mockMvc.perform(requestBuilder)
                .andExpect(status().isBadRequest());
    }

    @Test
    void testNonExistingUser() throws Exception {
        // Given
        Long nonExistingUserId = 100L;
        when(userService.verify(nonExistingUserId))
                .thenThrow(new UserNotFoundException(UserConstants.USER_NOT_FOUND));

        mockMvc.perform(get("/user-management/users/is_verified/{userId}", nonExistingUserId))
                .andExpect(status().isNotFound());
    }

    @Test
    void testVerifyUser_Successful() {
        String validToken = "eyJhbGciOiJIUzI1NiJ9.eyJlbWFpbCI6InZpa2FybWFfdmVtYnVsdXJ1QGVwYW0uY29tIiwic3ViIjoidmlrYXJtYV92ZW1idWx1cnVAZXBhbS5jb20iLCJpYXQiOjE3MTk0ODQ0NDMsImV4cCI6MTcxOTQ4NDUwM30.T0l-gkI3P5Axkp8ZfnhOXiTiMRwiTRYQq7WvEEXrc2E";
        UserResponse expectedResponse = new UserResponse(1L, EMAIL_VERIFICATION_SUCCESSFUL, VERIFIED);
        when(userService.verifyUser(validToken)).thenReturn(expectedResponse);

        UserResponse actualResponse = userService.verifyUser(validToken);

        assertEquals(expectedResponse, actualResponse);
        verify(userService, times(1)).verifyUser(validToken);
    }


    @Test
    void testVerifyUser_NotFound() {
        String invalidToken = "eyJhbGciOiJIUzI1NiJ9.eyJlbWFpbCI6InZpa2FybWFfdmVtYnVsdXJ1QGVwYW0uY29tIiwic3ViIjoidmlrYXJtYV92ZW1idWx1cnVAZXBhbS5jb20iLCJpYXQiOjE3MTk0ODQ0NDMsImV4cCI6MTcxOTQ4NDUwM30.T0l-gkI3P5Axkp8ZfnhOXiTiMRwiTRYQq7WvEEXrc2Edsd";
        when(userService.verifyUser(invalidToken)).thenThrow(UserNotFoundException.class);

        assertThrows(UserNotFoundException.class, () -> userService.verifyUser(invalidToken));
        verify(userService, times(1)).verifyUser(invalidToken);
    }

    @Test
    void testVerifyUserBadRequest() throws Exception {
        mockMvc.perform(get("/user-management/users/verify")
                        .param("mailId", mailId)
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest())
                .andExpect(result -> assertInstanceOf(MissingServletRequestParameterException.class, result.getResolvedException()));

        Mockito.verify(userService, Mockito.never()).verifyUser(token);
    }

    @Test
    void testVerifyUserWithoutMailId() throws Exception {
        mockMvc.perform(get("/user-management/users/verify")
                        .param("userId", userId.toString())
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest());

        Mockito.verify(userService, Mockito.never()).verifyUser(token);
    }

    @Test
    void testVerifyUserWithNonNumericUserId() throws Exception {
        mockMvc.perform(get("/user-management/users/verify")
                        .param("userId", "abc")
                        .param("mailId", mailId)
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest());

        Mockito.verify(userService, Mockito.never()).verifyUser(token);
    }

    @Test
    void testVerifyUserWithInvalidMailId() throws Exception {
        final String invalidToken = "eyJhbGciOiJIUzI1NiJ9.eyJlbWFpbCI6InZpa2FybWFfdmVtYnVsdXJ1QGVwYW0uY29tIiwic3ViIjoidmlrYXJtYV92ZW1idWx1cnVAZXBhbS5jb20iLCJpYXQiOjE3MTk0ODQ0NDMsImV4cCI6MTcxOTQ4NDUwM30.T0l-gkI3P5Axkp8ZfnhOXiTiMRwiTRYQq7WvEEXrc2E343dfs";
        final String invalidEmail = "user@sdnc.com";
        final String INVALID_MAIL_ID = "Invalid mail ID";

        when(jwtUtil.extractEmail(invalidToken)).thenReturn(invalidEmail);
        when(userService.verifyUser(invalidToken)).thenThrow(new IllegalArgumentException(INVALID_MAIL_ID));

        mockMvc.perform(get("/user-management/users/verify")
                        .param("token", invalidToken)
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest())
                .andExpect(result -> assertInstanceOf(IllegalArgumentException.class, result.getResolvedException()))
                .andExpect(result -> assertEquals(INVALID_MAIL_ID, Objects.requireNonNull(result.getResolvedException()).getMessage()));

        verify(userService, times(1)).verifyUser(invalidToken);
    }

    @Test
    void testVerifyUser_AlreadyVerified() {
        String verifiedToken = "eyJhbGciOiJIUzI1NiJ9.eyJlbWFpbCI6InZpa2FybWFfdmVtYnVsdXJ1QGVwYW0uY29tIiwic3ViIjoidmlrYXJtYV92ZW1idWx1cnVAZXBhbS5jb20iLCJpYXQiOjE3MTk0ODQ0NDMsImV4cCI6MTcxOTQ4NDUwM30.T0l-gkI3P5Axkp8ZfnhOXiTiMRwiTRYQq7WvEEXrc2E";
        BadRequestException exception = new BadRequestException(1L, "VERIFIED", "User already verified");
        when(userService.verifyUser(verifiedToken)).thenThrow(exception);

        Exception thrownException = assertThrows(BadRequestException.class, () -> userService.verifyUser(verifiedToken));
        assertEquals(exception, thrownException);
        verify(userService, times(1)).verifyUser(verifiedToken);
    }


    @Test
    void testRegisterUser_Successfully() throws Exception {

        userRequest.setUserName("Rohit");
        userRequest.setUserEmail("rohit@gmail.com");
        userRequest.setPassword("rohit@1234");

        mockMvc.perform(post("/user-management/users/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(userRequest)))
                .andExpect(status().isOk())
                .andExpect(content().string("User registered successfully and verification mail sent"));
    }

    @Test
     void testRegisterUser_WhenUserAlreadyExists() throws Exception {

        userRequest.setUserName("Rohit");
        userRequest.setUserEmail("rohit@gmail.com");
        userRequest.setPassword("rohit@1234");

        doThrow(new UserAlreadyExistsException("User already exists"))
                .when(userService).registerUser(any(UserRequest.class));

        mockMvc.perform(post("/user-management/users/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(userRequest)))
                .andExpect(status().isBadRequest());
    }

    @Test
     void testRegisterUser_WhenInvalidUserName() throws Exception {
        userRequest.setUserName("");
        userRequest.setUserEmail("user@gmail.com");
        userRequest.setPassword("test@123");

        doThrow(new InvalidUserNameException("Invalid user name"))
                .when(userService).registerUser(any(UserRequest.class));

        mockMvc.perform(post("/user-management/users/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(userRequest)))
                .andExpect(status().isBadRequest());
    }

    @Test
     void testRegisterUser_WhenUserNameIsNull() throws Exception {

        userRequest.setUserName(null);
        userRequest.setUserEmail("test@gmail.com");
        userRequest.setPassword("test@1234");

        doThrow(new InvalidUserNameException("Invalid user name"))
                .when(userService).registerUser(any(UserRequest.class));

        mockMvc.perform(post("/user-management/users/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(userRequest)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void testRegisterUser_WhenUserNameIsEmpty() throws Exception {

        userRequest.setUserName("");
        userRequest.setUserEmail("test@gmail.com");
        userRequest.setPassword("test@1234");

        doThrow(new InvalidUserNameException("Invalid user name"))
                .when(userService).registerUser(any(UserRequest.class));

        mockMvc.perform(post("/user-management/users/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(userRequest)))
                .andExpect(status().isBadRequest());
    }

    @Test
     void testRegisterUser_WhenInvalidEmailFormat() throws Exception {

        userRequest.setUserName("testuser");
        userRequest.setUserEmail("invalid format");
        userRequest.setPassword("Test@1234");

        doThrow(new InvalidEmailException("Invalid user email"))
                .when(userService).registerUser(any(UserRequest.class));

        mockMvc.perform(post("/user-management/users/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(userRequest)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void testRegisterUser_WhenPasswordIsInvalid() throws Exception {
        userRequest.setUserName("testuser");
        userRequest.setUserEmail("test@gmail.com");
        userRequest.setPassword("Test");

        doThrow(new InvalidPasswordException("Invalid Password"))
                .when(userService).registerUser(any(UserRequest.class));

        mockMvc.perform(post("/user-management/users/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(userRequest)))
                .andExpect(status().isBadRequest());
    }
    @Test
    void testChangePassword_Success() throws Exception {
        changePasswordUserRequest.setUserName("testUser");
        changePasswordUserRequest.setNewPassword("encryptedNewPassword");
        changePasswordUserRequest.setConfirmNewPassword("encryptedNewPassword");

        when(userService.changePasswordProcess(anyString(), anyString(), anyString())).thenReturn(PASSWORD_UPDATED_SUCCESSFULLY);

        mockMvc.perform(patch("/user-management/users/change-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"userName\":\"testUser\",\"newPassword\":\"encryptedNewPassword\",\"confirmNewPassword\":\"encryptedNewPassword\"}"))
                .andExpect(status().isOk())
                .andExpect(content().string(PASSWORD_UPDATED_SUCCESSFULLY));
    }

    @Test
    void testChangePassword_PasswordsDoNotMatch() throws Exception {
        changePasswordUserRequest.setUserName("testUser");
        changePasswordUserRequest.setNewPassword("encryptedNewPassword");
        changePasswordUserRequest.setConfirmNewPassword("encryptedDifferentPassword");

        doThrow(new PasswordsDoNotMatchException(NEW_PASSWORD_AND_CONFIRM_PASSWORD_DOES_NOT_MATCH)).when(userService).changePasswordProcess(anyString(), anyString(), anyString());

        mockMvc.perform(patch("/user-management/users/change-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"userName\":\"testUser\",\"newPassword\":\"encryptedNewPassword\",\"confirmNewPassword\":\"encryptedDifferentPassword\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(NEW_PASSWORD_AND_CONFIRM_PASSWORD_DOES_NOT_MATCH));
    }

    @Test
    void testChangePassword_UserNotFound() throws Exception {
        changePasswordUserRequest.setUserName("nonExistentUser");
        changePasswordUserRequest.setNewPassword("encryptedNewPassword");
        changePasswordUserRequest.setConfirmNewPassword("encryptedNewPassword");

        doThrow(new UserNotFoundException(USER_NOT_FOUND)).when(userService).changePasswordProcess(anyString(), anyString(), anyString());

        mockMvc.perform(patch("/user-management/users/change-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"userName\":\"nonExistentUser\",\"newPassword\":\"encryptedNewPassword\",\"confirmNewPassword\":\"encryptedNewPassword\"}"))
                .andExpect(status().isNotFound())
                .andExpect(content().string(USER_NOT_FOUND));
    }

    @Test
    void testChangePassword_NewPasswordMatchesOld() throws Exception {
        changePasswordUserRequest.setUserName("testUser");
        changePasswordUserRequest.setNewPassword("encryptedNewPassword");
        changePasswordUserRequest.setConfirmNewPassword("encryptedNewPassword");

        doThrow(new NewPasswordMatchesOldException(NEW_PASSWORD_AND_OLD_PASSWORD_SHOULD_NOT_BE_SAME)).when(userService).changePasswordProcess(anyString(), anyString(), anyString());

        mockMvc.perform(patch("/user-management/users/change-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"userName\":\"testUser\",\"newPassword\":\"encryptedNewPassword\",\"confirmNewPassword\":\"encryptedNewPassword\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(NEW_PASSWORD_AND_OLD_PASSWORD_SHOULD_NOT_BE_SAME));
    }

    @Test
    void testChangePassword_PasswordValidationFailure() throws Exception {
        changePasswordUserRequest.setUserName("testUser");
        changePasswordUserRequest.setNewPassword("short");
        changePasswordUserRequest.setConfirmNewPassword("short");

        doThrow(new IllegalArgumentException(PASSWORD_VALIDATION)).when(userService).changePasswordProcess(anyString(), anyString(), anyString());
        mockMvc.perform(patch("/user-management/users/change-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"userName\":\"testUser\",\"newPassword\":\"short\",\"confirmNewPassword\":\"short\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(CHECK_YOUR_PASSWORD_PATTERN + PASSWORD_VALIDATION));
    }

    @Test
    void testSignIn_Success() throws Exception {
        UserRequestV2 request = new UserRequestV2("validUsername", "validPassword");
        UserResponseV2 response = new UserResponseV2("validUsername", "user@example.com", "validToken");

        when(userService.signInProcess(any(UserRequestV2.class))).thenReturn(response);

        mockMvc.perform(post("/user-management/users/signin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(asJsonString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("validUsername"))
                .andExpect(jsonPath("$.email").value("user@example.com"))
                .andExpect(jsonPath("$.token").value("validToken"));
    }

    @Test
    void testSignIn_InvalidCredentials() throws Exception {
        UserRequestV2 request = new UserRequestV2("invalidUsername", "invalidPassword");

        when(userService.signInProcess(any(UserRequestV2.class))).thenThrow(new AuthenticationFailedException("Invalid credentials"));

        mockMvc.perform(post("/user-management/users/signin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(asJsonString(request)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(HttpStatus.UNAUTHORIZED.value()))
                .andExpect(jsonPath("$.message").value("Invalid credentials"))
                .andExpect(jsonPath("$.timestamp").exists());
    }

    @Test
    void testSignIn_UserNotVerified() throws Exception {
        UserRequestV2 request = new UserRequestV2("unverifiedUser", "password");

        when(userService.signInProcess(any(UserRequestV2.class))).thenThrow(new AuthenticationFailedException("User account is not verified"));

        mockMvc.perform(post("/user-management/users/signin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(asJsonString(request)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(HttpStatus.UNAUTHORIZED.value()))
                .andExpect(jsonPath("$.message").value("User account is not verified"))
                .andExpect(jsonPath("$.timestamp").exists());
    }

    @Test
    void testSignIn_MissingUsernameOrPassword() throws Exception {
        UserRequestV2 request = new UserRequestV2("", "");

        mockMvc.perform(post("/user-management/users/signin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(asJsonString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").exists());
    }

    @Test
    void testSignIn_MissingUsername() throws Exception {
        UserRequestV2 request = new UserRequestV2("", "password");

        mockMvc.perform(post("/user-management/users/signin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(asJsonString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").exists());
    }

    @Test
    void testSignIn_MissingPassword() throws Exception {
        UserRequestV2 request = new UserRequestV2("username", "");

        mockMvc.perform(post("/user-management/users/signin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(asJsonString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").exists());
    }


    @Test
    void validateAndExtract_ValidToken_ShouldReturnUsernameAndUserId() throws Exception {
        String username = "alex1";
        Long userId = 1L;
        List<Object> tokenInfo = Arrays.asList(username, userId);

        when(tokenService.validate(validToken)).thenReturn(tokenInfo);

        mockMvc.perform(get("/user-management/users/validate")
                        .param("token", validToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0]").value(username))
                .andExpect(jsonPath("$[1]").value(userId));
    }

    @Test
    void validateAndExtract_InvalidToken_ShouldReturnError() throws Exception {
        when(tokenService.validate(invalidToken)).thenThrow(new RuntimeException(INVALID_TOKEN_SIGNATURE));

        mockMvc.perform(get("/user-management/users/validate")
                        .param("token", invalidToken))
                .andExpect(status().isUnauthorized())
                .andExpect(content().string(containsString(INVALID_TOKEN_SIGNATURE)));
    }

    @Test
    void validateAndExtract_ExpiredToken_ShouldReturnError() throws Exception {
        when(tokenService.validate(expiredToken)).thenThrow(new JwtException(TOKEN_EXPIRED));

        mockMvc.perform(get("/user-management/users/validate")
                        .param("token", expiredToken))
                .andExpect(status().isUnauthorized())
                .andExpect(content().string(containsString(TOKEN_EXPIRED)));
    }

}

