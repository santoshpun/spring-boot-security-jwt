package com.santosh.springbootsecurityjwt.dto;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

public class JwtAuthenticationToken extends UsernamePasswordAuthenticationToken {
    private String token;

    public JwtAuthenticationToken(String token) {
        super(token, token);
        this.token = token;
    }

    public String getToken() {
        return token;
    }
}
