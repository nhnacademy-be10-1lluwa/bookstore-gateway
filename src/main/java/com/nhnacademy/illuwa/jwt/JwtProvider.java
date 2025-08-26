package com.nhnacademy.illuwa.jwt;

import com.nhnacademy.illuwa.dto.TokenValidationResult;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;
import org.springframework.util.StopWatch;

import java.security.Key;

@Slf4j
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

//    public boolean isAccessTokenBlacklisted(String accessToken) {
//        if (accessToken == null || accessToken.isEmpty()) {
//            return false;
//        }
//        return redisTemplate.hasKey("blacklist:access:" + accessToken);
//    }

    public TokenValidationResult validateTokenWithBlacklist(String token) {
        StopWatch sw = new StopWatch("JWT-Validation");

        try {
            // 1. JWT 서명/만료 검증
            sw.start("JWT-Parsing");
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
            sw.stop();

//            // 2. 블랙리스트 검증
//            sw.start("AT Blacklist-Check");
//            if (isAccessTokenBlacklisted(token)) {
//                return TokenValidationResult.blacklisted();
//            }
//            sw.stop();

            // 3. 성공
            sw.start("Claims-Processing");
            Long userId = Long.valueOf(claims.getSubject());
            String role = claims.get("role", String.class);
            sw.stop();

            logPerformance(sw);
            return TokenValidationResult.success(userId, role);

        } catch (ExpiredJwtException e) {
            logPerformance(sw);
            return TokenValidationResult.expired();
        } catch (Exception e) {
            logPerformance(sw);
            return TokenValidationResult.invalid();
        }
    }

    private void logPerformance(StopWatch sw) {
        log.info("JWT Validation Performance: total={}ms, details=\n{}",
                sw.getTotalTimeMillis(), sw.prettyPrint());
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