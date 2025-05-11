package com.dev.security.Config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

@Service
public class JwtService {

    @Value("${jwt.secret}")
    private String secret;

    public List<SimpleGrantedAuthority> extractAuthorities(String token) {
        // Extrae el claim "roles" y lo convierte en una lista de String
        List<String> roles = JWT.decode(token)
                .getClaim("roles")
                .asList(String.class);
        return roles.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }

    public String extractUsername(String token) {
        return JWT.decode(token).getSubject();
    }

    public String generateToken(UUID id, String email, List<String> roles) {
        Date now = new Date();
        Date expiration = new Date(now.getTime() + 1000 * 60 * 60 * 10);

        Algorithm algorithm = Algorithm.HMAC256(secret);

        return JWT.create()
                .withSubject(email)
                .withClaim("id",String.valueOf(id))
                .withArrayClaim("roles", roles.toArray(new String[0]))
                .withIssuedAt(now)
                .withExpiresAt(expiration)
                .sign(algorithm);
    }

    public boolean validateToken(String token) throws AuthenticationException {

        JWT.require(Algorithm.HMAC256(secret)).build().verify(token);

        return true;
    }

}