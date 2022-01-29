package com.santosh.springbootsecurityjwt.dto;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

public class BasicAuthToken extends UsernamePasswordAuthenticationToken {

    public BasicAuthToken(String username, String password) {
        super(username, password);
    }
}
