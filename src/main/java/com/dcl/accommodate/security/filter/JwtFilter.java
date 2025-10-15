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
    private final String PublicURL;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        log.info("Authenticating request via JwtFilter for type '{}'", jwtType);

        String publicURL = "/api/v1/public";

        if(! request.getRequestURI().contains(PublicURL)) {
            if(CurrentUser.getAuthentication().isEmpty()) {
                String token = request.getHeader(HttpHeaders.AUTHORIZATION);
                token = token != null
                        ? token.substring(7)
                        : "";

                if(! token.isBlank()) {
                   var jws = jwtService.getClaims(token);

                   if(isTypeValid(jws)) {
                       Claims claims = jws.getBody();

                       if(claims != null) {
                           String userId = claims.getSubject();
                           if(userId != null) {
                               var authorities = resolveGrantedAuthorities(claims); // never returns null
                               CurrentUser.setAuthentication(new UsernamePasswordAuthenticationToken(userId, null, authorities));
                               log.info("Authentication Successful for user: '{}'", userId);

                           } else log.warn("Authentication Failed. No Subject in JWT.");

                       } else log.warn("Authentication Failed. Couldn't extract JWT claims.");

                   } else log.warn("Authentication Failed. JWT type mismatch.");

                } else log.warn("Authentication Failed. JWT is Null or Blank.");

            } else log.info("Skipping Authentication in JWTFilter for '{}', User Already Authenticated", jwtType);
        }

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

    private boolean isTypeValid(Jws<Claims> jws) throws IOException, ServletException {
            String type = (String) jws.getHeader().get("type");
            return jwtType.name().equals(type);
    }
}
