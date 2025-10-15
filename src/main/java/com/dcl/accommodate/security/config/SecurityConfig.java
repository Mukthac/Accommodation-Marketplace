package com.dcl.accommodate.security.config;

import com.dcl.accommodate.security.filter.JwtFilter;
import com.dcl.accommodate.security.jwt.JwtService;
import com.dcl.accommodate.security.jwt.JwtType;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@AllArgsConstructor
public class SecurityConfig {

    private final JwtService jwtService;

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    @Order(2)
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.securityMatcher("/api/v1/**");
        configureFilterChainWithDefaults(http, JwtType.ACCESS);
        return http.build();
    }

    @Bean
    @Order(1)
    SecurityFilterChain refreshFilterChain(HttpSecurity http) throws Exception {
        http.securityMatcher("/api/v1/refresh/**");
        configureFilterChainWithDefaults(http, JwtType.REFRESH);
        return http.build();
    }

    private void configureFilterChainWithDefaults(HttpSecurity http, JwtType jwtType) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable);

        http.authorizeHttpRequests(authorize ->
                authorize.requestMatchers("/api/v1/public/**")
                        .permitAll()
                        .anyRequest().authenticated());

        http.addFilterBefore(
                JwtFilter.builder()
                        .jwtService(jwtService)
                        .jwtType(jwtType)
                        .build(),
                UsernamePasswordAuthenticationFilter.class);

        http.sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
    }


    @Bean
    AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
       return config.getAuthenticationManager();
    }
}
