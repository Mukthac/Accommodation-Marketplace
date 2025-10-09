package com.dcl.accommodate.service.contracts;


import com.dcl.accommodate.dto.request.UserRegistrationRequest;

public interface UserService {

    public void registerUser(UserRegistrationRequest registration);
}
