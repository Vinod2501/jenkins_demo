package com.epam.musicapp.user.management.constants;

public class UserConstants {

    public static final String VERIFICATION_STATUS_MUST_BE_VERIFIED = "verification_status must be 'verified'";
    private UserConstants() {
    }
    public static final String CHANGE_PASSWORD = "change-password";
    public static final String USER_NAME_CANNOT_BE_EMPTY = "User name cannot be empty";
    public static final String PASSWORD_CANNOT_BE_EMPTY = "Password cannot be empty";
    public static final String USER_NOT_FOUND = "User not found";
    public static final String EMAIL_VERIFICATION_UNSUCCESSFUL = "Email verification unsuccessful. User is already verified or not eligible for verification.";
    public static final String EMAIL_VERIFICATION_SUCCESSFUL = "Email verification successful.";
    public static final String INVALID_PARAMETER = "Invalid parameter: ";
    public static final String VERIFY_USER_SUMMARY = "Verify a user";
    public static final String VERIFY_USER_DESCRIPTION = "Verify a user by their userId and email";
    public static final String RESPONSE_DESCRIPTION_200 = "User verification successful";
    public static final String RESPONSE_DESCRIPTION_400 = "Invalid userId or mailId, or user is already verified";
    public static final String RESPONSE_DESCRIPTION_404 = "User not found";
    public static final String USER_VERIFIED = "User is verified";
    public static final String VERIFICATION_REQUIRED = "The user is not verified!!PLease verify your account";
    public static final String VERIFIED = "verified";
    public static final String INVALID_USER_ID = "Invalid User id : User id should only be a positive integer";
    public static final String VERIFY_USER = "Verify User";
    public static final String USER_CONTROLLER = "User Controller";
    public static final String PENDING = "pending";
    public static final String INVALID_CREDENTIALS = "Invalid email or password.";
    public static final String LOGIN_SUCCESS = "Login successful!";
    public static final String EMAIL = "test@epam.com";
    public static final String INVALID_EMAIL = "invalid@test.com";
    public static final String PASSWORD = "password";
    public static final String WRONG_PASSWORD = "wrongpassword";
    public static final String LOGIN_ENDPOINT = "/user-management/users/login";

    public static final String USER_ALREADY_EXISTS = "User already exists : Try with different email id/username";
    public static final String REGISTER_USER = "Register a new user";
    public static final String REGISTERED_SUCCESSFULLY = "User registered successfully and verification mail sent";
    public static final String SUBJECT = "Complete your Registration!";
    public static final String NULL_USERNAME = "User Name can't be null.";
    public static final String USERNAME_LENGTH = "Username should have minimum 5 characters and maximum 10 characters.";
    public static final String INVALID_USERNAME = "Username should contain only alphaNumeric Characters.";
    public static final String NULL_PASSWORD = "Password can't be null.";
    public static final String INVALID_PASSWORD = "Password must contain at least 8 characters, including alphanumeric and special characters.";
    public static final String NULL_EMAIL = "Email can't be null.";
    public static final String INVALID_EMAIL_FORMAT = "Invalid email format.";
    public static final String EMPTY_EMAIL = "Email can not be empty";
    public static final String EMAIL_PATTERN = "^[\\w-]+(\\.[\\w])*@(gmail\\.com|epam\\.com)$";
    public static final String PASSWORD_PATTERN = "^(?=.*[0-9])(?=.*[a-zA-Z])(?=.*[@#$%^&+=])(?=\\S+$).{8,}$";
    public static final String USERNAME_PATTERN = "^(?=.*[A-Za-z])[A-Za-z0-9]+$" ;
    public static final String INVALID_URL = "Invalid URL";
    public static final String PASSWORD_VALIDATION = "Password must be at least 8 characters long and not longer than 11, and include at least one uppercase letter, one lowercase letter, one digit, and one special character.";
    public static final String NEW_PASSWORD_AND_CONFIRM_PASSWORD_DOES_NOT_MATCH = "The new password and confirmation password do not match.";
    public static final String DECRYPTION_ERROR= "Error while decrypting: ";
    public static final String AES_TRANSFORMATION = "AES/ECB/PKCS5PADDING";

    public static final String SIGN_IN = "Sign In here";
    public static final String INVALID_CREDENTIALS_ERROR = "Invalid username or password.";

    public static final String PASSWORD_UPDATED_SUCCESSFULLY = "Password is updated successfully.";
    public static final String NEW_PASSWORD_AND_OLD_PASSWORD_SHOULD_NOT_BE_SAME = "New password and old password should not be same.";
    public static final String CHECK_YOUR_PASSWORD_PATTERN = "Invalid password format , Check your password pattern : ";
    public static final String USER_NAME_CANNOT_BE_NULL = "User name cannot be null";
    public static final String EMAIL_IS_MANDATORY = "Email is mandatory";
    public static final String PASSWORD_IS_MANDATORY = "Password is mandatory";
    public static final String  TOKEN_EXPIRED= "Token has expired";
    public static final String INVALID_TOKEN_SIGNATURE = "Invalid token signature";
    public static final String JSON_CONVERSION_ERROR = "Failed to convert object to JSON string";


    public static final String USER_ID = "userId";
    public static final String USERNAME = "username";



}
