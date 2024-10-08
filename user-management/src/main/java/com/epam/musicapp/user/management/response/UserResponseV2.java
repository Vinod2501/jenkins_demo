package com.epam.musicapp.user.management.response;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class UserResponseV2 {
    private String username;
    private String email;
    private String token;
}
