package com.santosh.springbootsecurityjwt.security.provider;

import com.santosh.springbootsecurityjwt.dto.BasicAuthToken;
import com.santosh.springbootsecurityjwt.service.AuthService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class BasicAuthProvider extends AbstractUserDetailsAuthenticationProvider {
    private AuthService authService;

    @Autowired
    public BasicAuthProvider(AuthService authService) {
        this.authService = authService;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(BasicAuthToken.class);
    }

    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
    }

    @Override
    protected UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
        log.info("Basic Auth provider is called " + username);

        return authService.loadUserByUsername(username);
    }
}
