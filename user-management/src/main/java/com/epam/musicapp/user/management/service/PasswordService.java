package com.epam.musicapp.user.management.service;

public interface PasswordService {

     String decryptPassword(String encryptedPassword) ;
     String encodePassword(String password) ;
     void validatePassword(String password) ;
     void checkPasswordsMatch( String newPassword, String confirmNewPassword) ;
     void checkNewPasswordAndOldPasswordMatch( String newPassword , String oldPasswordHash);
     boolean checkBcryptPassword(String decryptedPassword, String hashedPassword) ;



}
