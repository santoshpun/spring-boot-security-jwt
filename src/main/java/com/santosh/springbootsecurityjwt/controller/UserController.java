package com.santosh.springbootsecurityjwt.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@Slf4j
@RestController
@RequestMapping(value = "users")
public class UserController {

    @GetMapping()
    public List<String> getAllUsers() {
        return Arrays.asList("john", "steve");
    }
}
