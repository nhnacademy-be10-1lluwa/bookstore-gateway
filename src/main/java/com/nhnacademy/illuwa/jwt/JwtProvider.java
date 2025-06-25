package com.nhnacademy.illuwa.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.SignatureException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class JwtProvider {

    private final JwtProperties jwtProperties;

    public boolean validateToken(String token) {
        try {
            Jwts.parser()
                    .setSigningKey(jwtProperties.getSecret())
                    .parseClaimsJws(token);
            return true;
        } catch (SignatureException e) {
            return false;
        }
    }

    public Long getUserIdFromToken(String token) {
        Claims claims = Jwts.parser()
                .setSigningKey(jwtProperties.getSecret())
                .parseClaimsJws(token)
                .getBody();
        return Long.parseLong(claims.getSubject());
    }
}