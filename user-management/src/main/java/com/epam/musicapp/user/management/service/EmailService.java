package com.epam.musicapp.user.management.service;

import com.epam.musicapp.user.management.entity.User;

public interface EmailService {

    void sendVerificationEmail(User user);
}