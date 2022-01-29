package com.santosh.springbootsecurityjwt.util;

import com.santosh.springbootsecurityjwt.dto.AuthUser;
import com.santosh.springbootsecurityjwt.model.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.ArrayList;

@Slf4j
@Component
public class JwtUtil {

    @Value("${jwt.secret}")
    private String secret;

    /**
     * Tries to parse specified String as a JWT token. If successful, returns User object with username, id and role prefilled (extracted from token).
     * If unsuccessful (token is invalid or not containing all required user properties), simply returns null.
     *
     * @param token the JWT token to parse
     * @return the User object extracted from specified token or null if a token is invalid.
     */
    public AuthUser parseToken(String token) {
        try {
            Claims body = Jwts.parser()
                    .setSigningKey(secret)
                    .parseClaimsJws(token)
                    .getBody();

            long userId = Long.parseLong((String) body.get("userId"));
            String username = body.getSubject();

            return new AuthUser(userId, username, token, new ArrayList<>());
        } catch (JwtException | ClassCastException e) {
            log.error("Exception ", e);
            return null;
        }
    }

    /**
     * Generates a JWT token containing username as subject, and userId and role as additional claims. These properties are taken from the specified
     * User object. Tokens validity is infinite.
     *
     * @param authUser the user for which the token will be generated
     * @return the JWT token
     */
    public String generateToken(AuthUser authUser) {
        Claims claims = Jwts.claims().setSubject(authUser.getUsername());
        claims.put("userId", authUser.getUserId() + "");
        claims.put("role", authUser.getAuthorities());

        return Jwts.builder()
                .setClaims(claims)
                .signWith(SignatureAlgorithm.HS512, secret)
                .compact();
    }
}
