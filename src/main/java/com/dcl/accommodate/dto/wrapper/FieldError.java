package com.dcl.accommodate.dto.wrapper;

public record FieldError(
        String rejectedField,
        Object rejectedValue,
        String message
) {
}
