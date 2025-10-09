package com.dcl.accommodate.exceptions;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class UserAlreadyExistByEmailException extends RuntimeException {

    private final String message;

}
