package com.dcl.accommodate.dto.wrapper;

public record ApiResponse<T>(
        boolean success,
        String message,
        T data
) {
}
