package com.nhnacademy.illuwa.filter;

import com.nhnacademy.illuwa.dto.TokenValidationResult;
import com.nhnacademy.illuwa.jwt.JwtProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.*;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class JwtValidationFilter implements GlobalFilter {

    private final JwtProvider jwtProvider;
    private static final String CORRELATION_ID_HEADER = "X-Correlation-ID";

    // 인증 제외(Path 화이트리스트)
    private static final List<String> WHITE_LIST = List.of(
            "/api/auth/login", "/api/auth/signup", "/api/members/login",
            "/api/members/inactive-verifications", "/api/members/names", "/api/guests",
            "/api/books", "/api/search/category",
            "/api/order/guests",
            "/api/payments",
            "/api/public",
            "/docs", "/swagger-ui", "/v3/api-docs", "/swagger-ui.html",
            "/api/search"
    );

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String correlationId = extractOrGenerateCorrelationId(exchange);

        // 1. 화이트리스트 체크
        if(isExcludedPath(exchange.getRequest().getPath().value())) {
            return chain.filter(exchange);
        }

        // 2. 토큰 추출
        String accessToken = resolveToken(exchange);
        if(accessToken == null) {
            return unauthorized(exchange, "토큰이 없습니다.");
        }

        // 3. 토큰 검증
        TokenValidationResult result = jwtProvider.validateTokenWithBlacklist(accessToken);
        if (!result.isValid()) {
            if (result.isExpired()) {
                return unauthorized(exchange, "만료된 토큰입니다.");
            } else if (result.isBlacklisted()) {
                return unauthorized(exchange, "로그아웃된 토큰입니다.");
            } else {
                return unauthorized(exchange, "유효하지 않은 토큰입니다.");
            }
        }
        // 4. 검증 성공 시 헤더 추가
        return continueWithUserHeaders(accessToken, correlationId ,exchange, chain);
    }

    private String extractOrGenerateCorrelationId(ServerWebExchange exchange) {
        String correlationId = exchange.getRequest().getHeaders().getFirst(CORRELATION_ID_HEADER);
        if (correlationId == null || correlationId.isBlank()) {
            correlationId = UUID.randomUUID().toString();
        }
        return correlationId;
    }

    private Mono<Void> continueWithUserHeaders(String accessToken, String correlationId, ServerWebExchange exchange, GatewayFilterChain chain) {

        Long userId = jwtProvider.getUserIdFromToken(accessToken);
        String role   = jwtProvider.getRoleFromToken(accessToken);

        ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                .header("X-USER-ID",   String.valueOf(userId))
                .header("X-USER-ROLE", role)
                .header(CORRELATION_ID_HEADER, correlationId)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
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

    private Mono<Void> unauthorized(ServerWebExchange ex, String msg) {
        ex.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        ex.getResponse().getHeaders().setContentType(MediaType.TEXT_PLAIN);
        DataBuffer buf = ex.getResponse().bufferFactory().wrap(msg.getBytes(StandardCharsets.UTF_8));
        return ex.getResponse().writeWith(Mono.just(buf));
    }
}
