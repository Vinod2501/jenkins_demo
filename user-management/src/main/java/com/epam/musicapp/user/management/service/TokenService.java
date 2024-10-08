package com.epam.musicapp.user.management.service;

import java.util.List;

public interface TokenService {
    List<Object> validate(String token);
}
