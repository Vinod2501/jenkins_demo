package com.epam.musicapp.user.management.serviceimpl;

import com.epam.musicapp.user.management.service.TokenService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.*;

import static com.epam.musicapp.user.management.constants.UserConstants.*;


@Service
@RequiredArgsConstructor
public class TokenServiceImpl implements TokenService {

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Override
    public List<Object> validate(String token) {
        final Claims claims = getTokenDetails(token);
        checkTokenExpiration(claims);
        return extractTokenContent(claims);
    }

    private Claims getTokenDetails(String token) {
        SecretKey secretKey = Keys.hmacShaKeyFor(jwtSecret.getBytes());
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (ExpiredJwtException e) {
            throw new JwtException(TOKEN_EXPIRED);
        } catch (JwtException | IllegalArgumentException e) {
            throw new JwtException(INVALID_TOKEN_SIGNATURE, e);
        }
    }

    public void checkTokenExpiration(Claims claims) {
        if (claims.getExpiration().before(new Date())) {
            throw new JwtException(TOKEN_EXPIRED);
        }
    }

    public List<Object> extractTokenContent(Claims claims) {
        String username = claims.get(USERNAME, String.class);
        Long userId = claims.get(USER_ID, Long.class);
        if (username == null || userId == null) {
            throw new JwtException(INVALID_TOKEN_SIGNATURE);
        }
        return Arrays.asList(username, userId);
    }
}

