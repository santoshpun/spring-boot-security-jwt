package com.santosh.springbootsecurityjwt.controller.system;

import com.santosh.springbootsecurityjwt.dto.AuthUser;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping(value = "system")
public class WelcomeController {

    @GetMapping(value = "hello")
    public String hello(Authentication authentication) {
        AuthUser authUser = (AuthUser) authentication.getPrincipal();
        log.info("Logged in user : {}", authUser);
        return "Hello World !";
    }
}
