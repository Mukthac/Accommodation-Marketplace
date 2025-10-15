package com.dcl.accommodate.dto.request;


import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

public record UserLoginRequest(
        @NotNull(message = "email cannot be null")
        @NotBlank(message = "email cannot be blank")
        @Pattern(
                regexp = "^[\\w-\\.]+@([\\w-]+\\.)+[\\w-]{2,4}$",
                message = "Must be a valid email address"
        )
        @JsonProperty("email")
        String email,

        @NotNull(message = "password cannot be null")
        @NotBlank(message = "password cannot be blank")
        @Pattern(
                regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\|,.<>\\/?]).{8,20}$",
                message = " Must be 8 to 20 characters long. Must include at least one uppercase letter, one lowercase letter, one digit, and one special character."
        )
        @JsonProperty("password")
        String password
) {
}
