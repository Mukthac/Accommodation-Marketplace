package com.dcl.accommodate.exceptions.handler;

import com.dcl.accommodate.dto.wrapper.ApiAck;
import com.dcl.accommodate.exceptions.UserAlreadyExistByEmailException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class UserExceptionHandler {

    @ExceptionHandler(UserAlreadyExistByEmailException.class)
    public ResponseEntity<ApiAck> handleUserAlreadyExistByEmail(UserAlreadyExistByEmailException exception){
        return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(new ApiAck(false, exception.getMessage()));
    }
}
