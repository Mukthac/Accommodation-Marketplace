package com.dcl.accommodate.controller;

import com.dcl.accommodate.dto.request.UserLoginRequest;
import com.dcl.accommodate.dto.request.UserRegistrationRequest;
import com.dcl.accommodate.dto.response.AuthResponse;
import com.dcl.accommodate.dto.wrapper.ApiAck;
import com.dcl.accommodate.dto.wrapper.ApiResponse;
import com.dcl.accommodate.service.contracts.UserService;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;

@RestController
@RequestMapping("/api/v1")
@AllArgsConstructor
public class UserController {

    private final UserService userService;

    @PostMapping("/public/register")
    public ResponseEntity<ApiAck> registerUser(@Valid @RequestBody UserRegistrationRequest user){
        userService.registerUser(user);
        return ResponseEntity.created(URI.create("api/v1/profile"))
                .body(new ApiAck(true,"user registered successfully"));
    }

    @PostMapping("/public/login")
    public ResponseEntity<ApiResponse<AuthResponse>> loginUser(@Valid @RequestBody UserLoginRequest request){
        var response = userService.loginUser(request);
        return ResponseEntity.ok(new ApiResponse<>(
                true,
                "User Successfully Logged In",
                response
        ));
    }

    @PostMapping("/refresh")
    public ResponseEntity<ApiResponse<AuthResponse>> refreshLogin() {
        var response = userService.refreshLogin();
    }
}
