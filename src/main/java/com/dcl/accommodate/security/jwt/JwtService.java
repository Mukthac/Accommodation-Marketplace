package com.dcl.accommodate.security.jwt;

import com.dcl.accommodate.config.AppEnv;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.time.Duration;
import java.util.Base64;
import java.util.Date;
import java.util.Map;

/*
 * class is responsible for Token generation
 */
@Service
public class JwtService {
    private final Key key;
    private final AppEnv env;

    public JwtService(AppEnv env) {
        this.env = env;
        this.key = Keys.hmacShaKeyFor(Base64.getDecoder().decode(env.getJwt().getSecret()));
    }

    public record TokenConfig(
            Map<String, Object> claims,
            String subject,
            JwtType jwtType
    ) {
    }

    public record TokenResult(
            String token,
            Duration ttl
    ) {
    }

    public TokenResult generateToken(TokenConfig config) {
        var systemMillis = System.currentTimeMillis();

        Duration ttl = config.jwtType.equals(JwtType.ACCESS)
                ? env.getJwt().getAccessTtl()
                : env.getJwt().getRefreshTtl();

        String token = Jwts.builder()
                .setHeaderParam("type", config.jwtType.name())
                .setClaims(config.claims)
                .setIssuedAt(new Date(systemMillis))
                .setExpiration(new Date(systemMillis + ttl.toMillis()))
                .setSubject(config.subject)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        return new TokenResult(token, ttl);
    }


    public Jws<Claims> getClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()//return a parser to parse JWT
                .parseClaimsJws(token);
    }

}
