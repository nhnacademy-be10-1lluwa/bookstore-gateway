package com.nhnacademy.illuwa.jwt;

import com.nhnacademy.illuwa.dto.TokenValidationResult;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;

@Component
@RequiredArgsConstructor
public class JwtProvider {

    @Value("${jwt.secret}")
    private String secret;

    private final RedisTemplate<String, String> redisTemplate;
    private Key key;

    @PostConstruct
    public void init() {
        byte[] keyBytes = java.util.Base64.getDecoder().decode(secret);
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (SignatureException e) {
            return false;
        }
    }

    public boolean isAccessTokenBlacklisted(String accessToken) {
        if (accessToken == null || accessToken.isEmpty()) {
            return false;
        }
        return redisTemplate.hasKey("blacklist:access:" + accessToken);
    }

    public TokenValidationResult validateTokenWithBlacklist(String token) {
        try {
            // 1. JWT 서명/만료 검증
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            // 2. 블랙리스트 검증
            if (isAccessTokenBlacklisted(token)) {
                return TokenValidationResult.blacklisted();
            }

            // 3. 성공
            Long userId = Long.valueOf(claims.getSubject());
            String role = claims.get("role", String.class);
            return TokenValidationResult.success(userId, role);

        } catch (ExpiredJwtException e) {
            return TokenValidationResult.expired();
        } catch (Exception e) {
            return TokenValidationResult.invalid();
        }
    }

    public Claims getClaims(String token) {
        return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();
    }

    public Long getUserIdFromToken(String token) {
        return Long.valueOf(getClaims(token).getSubject());
    }

    public String getRoleFromToken(String token) {
        return getClaims(token).get("role", String.class);
    }
}