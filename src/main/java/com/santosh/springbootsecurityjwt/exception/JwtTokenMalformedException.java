package com.santosh.springbootsecurityjwt.exception;

public class JwtTokenMalformedException extends RuntimeException {

    public JwtTokenMalformedException(String message) {
        super(message);
    }
}
