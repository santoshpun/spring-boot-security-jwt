package com.santosh.springbootsecurityjwt.controller;

import com.santosh.springbootsecurityjwt.dto.AuthUser;
import com.santosh.springbootsecurityjwt.dto.request.LoginRequest;
import com.santosh.springbootsecurityjwt.dto.response.LoginResponse;
import com.santosh.springbootsecurityjwt.util.JwtUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping(value = "login")
public class LoginController {
    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtil jwtUtil;

    @PostMapping
    public ResponseEntity<?> doLogin(@RequestBody LoginRequest loginRequest) throws Exception {
        log.info("do login method called with details : {}", loginRequest);

        Authentication authentication = authenticate(loginRequest.getUsername(), loginRequest.getPassword());

        AuthUser userDetails = (AuthUser) authentication.getPrincipal();

        final String token = jwtUtil.generateToken(userDetails);

        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.AUTHORIZATION, "Bearer " + token);

        return ResponseEntity.ok().headers(headers).body(new LoginResponse(token));
    }

    private Authentication authenticate(String username, String password) throws Exception {
        try {
            return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
        } catch (BadCredentialsException e) {
            throw new Exception("INVALID_CREDENTIALS", e);
        }
    }
}
