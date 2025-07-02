package com.nhnacademy.illuwa.filter;

import com.nhnacademy.illuwa.jwt.JwtProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.Set;

@Component
@RequiredArgsConstructor
public class JwtAuthGatewayFilter implements GlobalFilter {

    private final JwtProvider jwtProvider;

    // 인증 제외(Path 화이트리스트)
    private static final Set<String> WHITE_LIST = Set.of(
            "/auth", "/login", "/signup", "/static", "/actuator"
    );

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        // 화이트 리스트 경로는 패스
        if(isExcludedPath(exchange.getRequest().getPath().value())) {
            return chain.filter(exchange);
        }

        // 토큰 추출 - Authorization > 쿠키
        String token = resolveToken(exchange);

        if(token == null) {
            return unauthorized(exchange, "토큰이 없습니다.");
        }
        if(!jwtProvider.validateToken(token)) {
            return unauthorized(exchange, "만료된 토큰입니다.");
        }

        // 클레임 추출
        Long userId = jwtProvider.getUserIdFromToken(token);
        String role = jwtProvider.getRoleFromToken(token);

        // 내부 헤더 주입
        ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                .header("X-USER-ID", userId.toString())
                .header("X-USER-ROLE", role)
                .build();

        return chain.filter(exchange.mutate().request(mutatedRequest).build());
    }

    // Authorization 헤더 우선, 없으면 ACCESS_TOKEN 쿠키
    private String resolveToken(ServerWebExchange exchange) {
        String auth = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if(auth != null && auth.startsWith("Bearer ")) {
            return auth.substring(7);
        }
        HttpCookie cookie = exchange.getRequest().getCookies().getFirst("ACCESS_TOKEN");
        return cookie != null ? cookie.getValue() : null;
    }

    private boolean isExcludedPath(String path) {
        return WHITE_LIST.stream().anyMatch(path::startsWith);
    }

    private Mono<Void> unauthorized(ServerWebExchange exchange, String message) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        byte[] bytes = message.getBytes(StandardCharsets.UTF_8);
        DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(bytes);
        return exchange.getResponse().writeWith(Mono.just(buffer));
    }
}
