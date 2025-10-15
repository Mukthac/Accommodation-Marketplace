package com.dcl.accommodate.dto.response;

import com.fasterxml.jackson.annotation.JsonProperty;

public record AuthResponse(
        @JsonProperty("user_id")
        String userId,

        @JsonProperty("access_token")
        String accessToken,

        @JsonProperty("access_validity")
        long accessValidity,

        @JsonProperty("refresh_token")
        String refreshToken,

        @JsonProperty("refresh_validity")
        long refreshValidity
) {
}
