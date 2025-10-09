package com.dcl.accommodate.dto.request;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

import java.time.LocalDate;

public record UserRegistrationRequest(

        @NotNull(message = "first_name cannot be null")
        @NotBlank(message = "first_name cannot be blank")
        @Pattern(
                regexp = "^[A-Z][a-zA-Z\\s'-]{1,49}$",
                message = "first_name must start with a capital letter and can have spaces and hyphens and apostrophes and must be between 2 to 50 characters"
        )
        @JsonProperty("first_name")
        String firstName,

        @NotNull(message = "first_name cannot be null")
        @NotBlank(message = "first_name cannot be blank")
        @Pattern(
                regexp = "^[A-Z][a-zA-Z\\s'-]{0,49}$",
                message = "last_name must be between 1 to 50 characters long"
        )
        @JsonProperty("last_name")
        String lastName,

        @NotNull(message = "email cannot be null")
        @NotBlank(message = "email cannot be blank")
        @Pattern(
                regexp = "^[\\w-\\.]+@([\\w-]+\\.)+[\\w-]{2,4}$",
                message = "Must be a valid email address"
        )
        @JsonProperty("email")
        String email,

        @NotNull(message = "phone_number cannot be null")
        @NotBlank(message = "phone_number cannot be blank")
        @Pattern(
                regexp = "^(\\+91[\\-\\s]?)?[6-9]\\d{9}$",
                message = "Invalid Indian phone number. It must start with digits 6–9 and be 10 digits long (optionally prefixed by +91)."
        )
        @JsonProperty("phone_number")
        String phoneNumber,

        @JsonFormat(pattern = "yyyy-MM-dd", shape = JsonFormat.Shape.STRING)
        @JsonProperty("date_of_birth")
        LocalDate dateOfBirth,


        @NotNull(message = "password cannot be null")
        @Pattern(
                regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\|,.<>\\/?]).{8,20}$",
                message = " Must be 8 to 20 characters long. Must include at least one uppercase letter, one lowercase letter, one digit, and one special character."
        )
        @JsonProperty("password")
        String password
){}