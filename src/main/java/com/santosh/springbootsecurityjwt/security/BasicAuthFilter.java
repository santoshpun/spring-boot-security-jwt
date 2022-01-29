package com.santosh.springbootsecurityjwt.security;

import com.santosh.springbootsecurityjwt.dto.BasicAuthToken;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Base64;

@Slf4j
public class BasicAuthFilter extends AbstractAuthenticationProcessingFilter {

    protected BasicAuthFilter(RequestMatcher requestMatcher, AuthenticationManager authenticationManager) {
        super(requestMatcher, authenticationManager);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        log.info("Basic auth attempt method called");

        String header = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (header == null) {
            throw new RuntimeException("Basic auth header missing");
        }

        log.info("Basic auth header : {}", header);

        String encodedCredentials = header.substring(6);

        log.info("Encoded credentials : {}", encodedCredentials);

        String decodedCredentials = new String(Base64.getDecoder().decode(encodedCredentials));

        log.info("Decoded credentials : {}", decodedCredentials);

        String[] pair = decodedCredentials.split(":");

        String username = pair[0];
        String password = pair[1];

        log.info("Username : {}", username);
        log.info("Password : {}", password);

        BasicAuthToken authRequest = new BasicAuthToken(username, password);

        return getAuthenticationManager().authenticate(authRequest);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult)
            throws IOException, ServletException {
        super.successfulAuthentication(request, response, chain, authResult);

        chain.doFilter(request, response);
    }
}
