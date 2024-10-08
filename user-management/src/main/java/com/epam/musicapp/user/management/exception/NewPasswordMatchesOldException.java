package com.epam.musicapp.user.management.exception;

public class NewPasswordMatchesOldException extends RuntimeException {
    public NewPasswordMatchesOldException(String message) {
        super(message);
    }
}
