package com.dcl.accommodate.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.time.Duration;

@Getter
@Setter
@Component
@ConfigurationProperties(prefix = "app")
public class AppEnv {

    private String baseURI;
    private Jwt jwt;

    @Getter
    @Setter
    public static class Jwt{
        private String secret;
        private Duration accessTtl; // access-ttl
        private Duration refreshTtl; //refresh-ttl
    }
}
