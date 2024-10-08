package com.epam.musicapp.user.management.controller;

import com.epam.musicapp.user.management.exception.InvalidCredentialsException;
import com.epam.musicapp.user.management.request.UserRequest;
import com.epam.musicapp.user.management.request.UserRequestV2;
import com.epam.musicapp.user.management.response.UserResponse;
import com.epam.musicapp.user.management.response.UserResponseV2;
import com.epam.musicapp.user.management.request.ChangePasswordUserRequest;
import com.epam.musicapp.user.management.service.TokenService;
import com.epam.musicapp.user.management.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.List;

import static com.epam.musicapp.user.management.constants.UserConstants.*;

@Tag(name = USER_CONTROLLER)
@RestController
@Validated
@RequestMapping("/user-management/users")
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;
    private final TokenService tokenService;


@ApiResponse(responseCode = "200", description = PASSWORD_UPDATED_SUCCESSFULLY)
@ApiResponse(responseCode = "400", description = CHECK_YOUR_PASSWORD_PATTERN + " : " + PASSWORD_VALIDATION)
@ApiResponse(responseCode = "404", description = USER_NOT_FOUND)
@PatchMapping(CHANGE_PASSWORD)
public ResponseEntity<String> changePassword(@RequestBody @Valid ChangePasswordUserRequest changePasswordUserRequest) {
    userService.changePasswordProcess(changePasswordUserRequest.getUserName(), changePasswordUserRequest.getNewPassword(), changePasswordUserRequest.getConfirmNewPassword());
    return ResponseEntity.ok(PASSWORD_UPDATED_SUCCESSFULLY);
}

    @ApiResponse(responseCode = "200", description = USER_VERIFIED)
    @ApiResponse(responseCode = "401", description = VERIFICATION_REQUIRED)
    @ApiResponse(responseCode = "404", description = USER_NOT_FOUND)
    @ApiResponse(responseCode = "400", description = INVALID_USER_ID)
    @Operation(summary = VERIFY_USER)
    @GetMapping("is_verified/{userId}")
    public ResponseEntity<UserResponse> verifyUser(@PathVariable Long userId) {
        UserResponse response = userService.verify(userId);
        return response.getVerificationStatus().equalsIgnoreCase(PENDING) ?
                ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response) :
                ResponseEntity.ok().body(response);
    }

    @PostMapping("/login")
    public ResponseEntity<UserResponse> login(@Valid @RequestBody UserRequest request) {
        try {
            UserResponse responseDTO = userService.login(request);
            return ResponseEntity.ok(responseDTO);
        } catch (InvalidCredentialsException ex) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new UserResponse(ex.getMessage()));
        }
    }

    @Operation(summary = VERIFY_USER_SUMMARY, description = VERIFY_USER_DESCRIPTION)
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = RESPONSE_DESCRIPTION_200),
            @ApiResponse(responseCode = "400", description = RESPONSE_DESCRIPTION_400),
            @ApiResponse(responseCode = "404", description = RESPONSE_DESCRIPTION_404)
    })
    @GetMapping(value = "/verify")
    public ResponseEntity<UserResponse> verifyUser(@RequestParam String token) {
        UserResponse responseDTO = userService.verifyUser(token);
        HttpStatus status = "verified".equals(responseDTO.getVerificationStatus()) ? HttpStatus.OK : HttpStatus.BAD_REQUEST;
        return new ResponseEntity<>(responseDTO, status);
    }


    @Operation(summary = REGISTER_USER)
    @ApiResponse(responseCode = "200", description = REGISTERED_SUCCESSFULLY)
    @ApiResponse(responseCode = "400", description = INVALID_CREDENTIALS)
    @ApiResponse(responseCode = "400", description = USER_ALREADY_EXISTS)
    @PostMapping("/signup")
    public ResponseEntity<String> registerUser(@RequestBody UserRequest userRequest) {
        userService.registerUser(userRequest);
        return ResponseEntity.ok(REGISTERED_SUCCESSFULLY);
    }


    @Operation(summary = SIGN_IN)
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = LOGIN_SUCCESS),
            @ApiResponse(responseCode = "400", description = INVALID_CREDENTIALS)
    })
    @PostMapping("/signin")
    public ResponseEntity<UserResponseV2> signIn(@Valid @RequestBody UserRequestV2 request) {
        return ResponseEntity.ok(userService.signInProcess(request));
    }


    @GetMapping("/validate")
    public ResponseEntity<List<Object>> validateAndExtract(@RequestParam("token") String jwtToken) {
        List<Object> tokenInfo = tokenService.validate(jwtToken);
        return ResponseEntity.ok(tokenInfo);
    }

    @GetMapping("/is_exist/{userName}")
    public ResponseEntity<Boolean> isUserExist(@PathVariable String userName) {
        return ResponseEntity.ok(userService.isUserExists(userName));
    }

}