package com.nhnacademy.illuwa.filter;

import com.nhnacademy.illuwa.exception.UnauthorizedException;
import com.nhnacademy.illuwa.jwt.JwtProvider;
import lombok.RequiredArgsConstructor;
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
        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        // /auth 경로는 인증 제외 (회원 가입, 로그인)
        if(request.getPath().toString().startsWith("/auth")) {
            return chain.filter(exchange);
        }

        if(authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new UnauthorizedException("Authorization 헤더가 없습니다.");
        }

        String token = authHeader.substring("Bearer ".length());

        if(!jwtProvider.validateToken(token)) {
            throw new UnauthorizedException("유효하지 않은 JWT 토큰");
        }

        Long userId = jwtProvider.getUserIdFromToken(token);

        ServerHttpRequest mutatedRequest = request.mutate()
                        .header("X-USER-ID", userId.toString())
                        .build();
        ServerWebExchange mutatedExchange = exchange.mutate().request(mutatedRequest).build();

        return chain.filter(mutatedExchange);
    }
}
