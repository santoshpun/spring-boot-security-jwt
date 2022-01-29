package com.santosh.springbootsecurityjwt.exception;

public class ServerException extends RuntimeException{

    public ServerException(String message){
        super(message);
    }
}
