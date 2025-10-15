package com.dcl.accommodate.security.config;

import com.dcl.accommodate.security.filter.JwtFilter;
import com.dcl.accommodate.security.jwt.JwtService;
import com.dcl.accommodate.security.jwt.JwtType;
import com.dcl.accommodate.util.UriBuilder;
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
    private final UriBuilder uriBuilder;

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    @Order(2)
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.securityMatcher(uriBuilder.buildPublicURI("/api/v1/**").toString());
        configureFilterChainWithDefaults(http, JwtType.ACCESS);
        return http.build();
    }

    @Bean
    @Order(1)
    SecurityFilterChain refreshFilterChain(HttpSecurity http) throws Exception {
        http.securityMatcher(uriBuilder.buildURI("/api/v1/refresh/**").toString());
        configureFilterChainWithDefaults(http, JwtType.REFRESH);
        return http.build();
    }

    private void configureFilterChainWithDefaults(HttpSecurity http, JwtType jwtType) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(
                                uriBuilder.buildPublicURI("/api/v1/public/**").toString())
                        .permitAll()
                        .anyRequest()
                        .authenticated());

        http.addFilterBefore(
                new JwtFilter(jwtService,jwtType,uriBuilder.buildPublicURI("").toString())
                ,UsernamePasswordAuthenticationFilter.class);


        http.sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
    }


    @Bean
    AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
       return config.getAuthenticationManager();
    }
}
