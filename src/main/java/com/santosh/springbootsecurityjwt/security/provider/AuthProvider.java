package com.santosh.springbootsecurityjwt.security.provider;

import com.santosh.springbootsecurityjwt.dto.AuthUser;
import com.santosh.springbootsecurityjwt.dto.JwtAuthenticationToken;
import com.santosh.springbootsecurityjwt.exception.JwtTokenMalformedException;
import com.santosh.springbootsecurityjwt.service.AuthService;
import com.santosh.springbootsecurityjwt.util.JwtUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class AuthProvider extends AbstractUserDetailsAuthenticationProvider {
    private JwtUtil jwtUtil;
    private AuthService authService;

    @Autowired
    public AuthProvider(JwtUtil jwtUtil, AuthService authService) {
        this.jwtUtil = jwtUtil;
        this.authService = authService;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(JwtAuthenticationToken.class);
    }

    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
    }

    @Override
    protected UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
        log.info("Auth provider is called " + username);

        JwtAuthenticationToken jwtAuthenticationToken = (JwtAuthenticationToken) authentication;

        String token = jwtAuthenticationToken.getToken();

        log.info("Token : {}", token);

        AuthUser user = jwtUtil.parseToken(token);

        if (user == null) {
            throw new JwtTokenMalformedException("JWT token is not valid");
        }

        return authService.loadUserByUsername(user.getUsername());
    }
}
