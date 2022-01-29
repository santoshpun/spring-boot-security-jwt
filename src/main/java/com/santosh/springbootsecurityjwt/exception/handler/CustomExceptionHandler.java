package com.santosh.springbootsecurityjwt.exception.handler;

import com.santosh.springbootsecurityjwt.dto.ErrorResponse;
import com.santosh.springbootsecurityjwt.exception.RecordNotFoundException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.util.Date;

@Slf4j
@RestControllerAdvice
public class CustomExceptionHandler extends ResponseEntityExceptionHandler {

    @ExceptionHandler(RecordNotFoundException.class)
    public final ResponseEntity<ErrorResponse> handleUserNotFoundException(RecordNotFoundException ex) {
        log.error("Exception ", ex);

        ErrorResponse error = new ErrorResponse("1", ex.getMessage(),
                HttpStatus.NOT_FOUND.value(), new Date());
        return new ResponseEntity<>(error, HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler(Exception.class)
    public final ResponseEntity<Object> handleAllExceptions(Exception ex, WebRequest request) {
        log.error("Exception ", ex);

        ErrorResponse error = new ErrorResponse("1", "Internal Server Error",
                HttpStatus.INTERNAL_SERVER_ERROR.value(), new Date());
        return new ResponseEntity<>(error, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @ExceptionHandler(RuntimeException.class)
    public final ResponseEntity<Object> handleRuntimeException(Exception ex) {
        log.error("Exception ", ex);

        ErrorResponse error = new ErrorResponse("1", "Internal Server Error",
                HttpStatus.INTERNAL_SERVER_ERROR.value(), new Date());
        return new ResponseEntity<>(error, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(MethodArgumentNotValidException ex,
                                                                  HttpHeaders headers, HttpStatus status, WebRequest request) {
        log.error("Exception ", ex);
        ErrorResponse error = new ErrorResponse("1", "Bad Request",
                HttpStatus.BAD_REQUEST.value(), new Date());
        return handleExceptionInternal(ex, error, headers, HttpStatus.BAD_REQUEST, request);
    }
}
