package com.nhnacademy.illuwa.filter;

import com.nhnacademy.illuwa.exception.UnauthorizedException;
import com.nhnacademy.illuwa.jwt.JwtProvider;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter implements WebFilter {

    private final JwtProvider jwtProvider;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        HttpCookie cookie = exchange.getRequest().getCookies().getFirst("ACCESS_TOKEN");

        // /auth 경로는 인증 제외 (회원 가입, 로그인)
        String path = request.getPath().toString();
        if(path.equals("/auth/login") || path.equals("/auth/signup")) {
            return chain.filter(exchange);
        }

        if (cookie == null) {
            return Mono.error(new UnauthorizedException("쿠키에 토큰이 없습니다."));
        }

        String token = cookie.getValue();
        if (!jwtProvider.validateToken(token)) {
            return Mono.error(new UnauthorizedException("유효하지 않은 토큰입니다."));
        }

        // jwt 토큰 파싱
        Long userId = jwtProvider.getUserIdFromToken(token);
        String role = jwtProvider.getRoleFromToken(token);

        if(path.startsWith("/admin") && !"ADMIN".equals(role)) {
            return Mono.error(new UnauthorizedException("접근 권한이 없습니다."));
        }

        ServerHttpRequest mutatedRequest = request.mutate()
                .header("X-USER-ID", userId.toString())
                .header("X-USER-ROLE", role)
                .build();

        return chain.filter(exchange.mutate().request(mutatedRequest).build());
    }
}
