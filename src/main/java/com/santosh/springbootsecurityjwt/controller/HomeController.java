package com.santosh.springbootsecurityjwt.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping(value = "api")
public class HomeController {

    @GetMapping(value = "hello")
    public String hello() {
        String loggedInUser = SecurityContextHolder.getContext().getAuthentication().getName();
        log.info("Logged in user : {}", loggedInUser);
        return "Hello World !";
    }
}
