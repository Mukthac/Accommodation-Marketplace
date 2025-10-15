package com.dcl.accommodate.security.filter;

import com.dcl.accommodate.security.jwt.JwtService;
import com.dcl.accommodate.security.jwt.JwtType;
import com.dcl.accommodate.security.util.CurrentUser;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Slf4j
@AllArgsConstructor
@Builder
public class JwtFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final JwtType jwtType;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        if(CurrentUser.getAuthentication().isPresent()) {
            log.info("Request is already Authenticated, skipping authentication in JwtFilter for type '{}'", jwtType.name());
            filterChain.doFilter(request, response);
        }

        var token = safeExtractToken(request, response, filterChain);
        var jws = jwtService.getClaims(token);

        matchType(request, response, filterChain, jws);

        Claims claims = jws.getBody();
        String userId = claims.getSubject();
        if (userId == null) logAndForward("invalid subject in JWT, Invalid JWT", request, response, filterChain);
        var authorities = resolveGrantedAuthorities(claims);

        var unPwdToken = new UsernamePasswordAuthenticationToken(userId, null, authorities);
        CurrentUser.setAuthentication(unPwdToken);

        filterChain.doFilter(request, response);
    }

    private List<GrantedAuthority> resolveGrantedAuthorities(Claims claims) {
        var roleInJwt = claims.get("role");

        String role = null;
        if (roleInJwt instanceof String r)
            role = r;

        List<GrantedAuthority> authorities = null;

        if (role == null) authorities = List.of();
        else authorities = List.of(new SimpleGrantedAuthority(role));
        return authorities;
    }

    private void matchType(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain, Jws<Claims> jws) throws IOException, ServletException {
        try {
            String type = (String) jws.getHeader().get("type");
            if(!type.equalsIgnoreCase(jwtType.name())) throw new JwtException("Invalid Jwt Type.");
        } catch (ClassCastException | NullPointerException | JwtException e) {
            logAndForward("Invalid Jwt Type", request, response, filterChain);
        }
    }

    private String safeExtractToken(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {
        try {
            String token = request.getHeader(HttpHeaders.AUTHORIZATION);
            token = token.substring(7);
            if(token.isBlank()) throw new JwtException("Invalid JWT token");
            else return token;
        } catch (NullPointerException | JwtException e) {
            logAndForward("Token not found in the request.", request, response, filterChain);
        }
        return null; // Unreached - either returns valid token or forwards the request
    }

    private void logAndForward(String message, HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {
        log.warn(message);
        filterChain.doFilter(request, response);
    }
}
