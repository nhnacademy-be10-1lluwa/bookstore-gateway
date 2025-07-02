package com.nhnacademy.illuwa.filter;

import com.nhnacademy.illuwa.jwt.JwtProvider;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;

@Component
public class JwtAuthGatewayFilter implements GlobalFilter {

    private final JwtProvider jwtProvider;

    public JwtAuthGatewayFilter(JwtProvider jwtProvider) {
        this.jwtProvider = jwtProvider;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        HttpCookie cookie = request.getCookies().getFirst("ACCESS_TOKEN");

        String path = request.getPath().value();

        // 인증 제외 경로
        if (isExcludedPath(path)) {
            return chain.filter(exchange);
        }

        if (cookie == null) {
            return unauthorized(exchange, "토큰이 없습니다.");
        }

        String token = cookie.getValue();

        if (!jwtProvider.validateToken(token)) {
            return unauthorized(exchange, "유효하지 않은 토큰입니다.");
        }

        Long userId = jwtProvider.getUserIdFromToken(token);
        String role = jwtProvider.getRoleFromToken(token);

        // 헤더에 유저 정보 추가
        ServerHttpRequest mutatedRequest = request.mutate()
                .header("X-USER-ID", userId.toString())
                .header("X-USER-ROLE", role)
                .build();

        return chain.filter(exchange.mutate().request(mutatedRequest).build());
    }

    private boolean isExcludedPath(String path) {
        return path.startsWith("/auth/")
                || path.equals("/")
                || path.startsWith("/static/")
                || path.startsWith("/login")
                || path.startsWith("/signup");
    }

    private Mono<Void> unauthorized(ServerWebExchange exchange, String message) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        byte[] bytes = message.getBytes(StandardCharsets.UTF_8);
        DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(bytes);
        return exchange.getResponse().writeWith(Mono.just(buffer));
    }
}
