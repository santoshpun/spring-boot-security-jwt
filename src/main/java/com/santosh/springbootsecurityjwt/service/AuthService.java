package com.santosh.springbootsecurityjwt.service;

import com.santosh.springbootsecurityjwt.dto.AuthUser;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Optional;

@Slf4j
@Service
public class AuthService implements UserDetailsService {

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.info("Authenticate user for username : {}", username);

        if (validateDummyUser(username)) {
            return new AuthUser(1, username, "$2a$12$2JEtsGvBzEPV67mwOS3i8OTDSw0nFbxN9RZ.ohSYjkvG3sR.vYAYW",
                    new ArrayList<>());
        } else {
            throw new UsernameNotFoundException("User not found with username: " + username);
        }
    }

    private boolean validateDummyUser(String loginUser) {
        Optional<String> obtainedUser = Arrays.asList("admin", "user", "santosh")
                .stream()
                .filter(user -> user.equalsIgnoreCase(loginUser))
                .findFirst();

        if (obtainedUser.isPresent()) {
            return true;
        }
        return false;
    }
}
