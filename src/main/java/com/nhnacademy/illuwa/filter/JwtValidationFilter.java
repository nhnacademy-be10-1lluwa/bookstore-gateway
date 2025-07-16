package com.nhnacademy.illuwa.filter;

import com.nhnacademy.illuwa.client.AuthClient;
import com.nhnacademy.illuwa.dto.TokenRefreshRequest;
import com.nhnacademy.illuwa.dto.TokenResponse;
import com.nhnacademy.illuwa.jwt.JwtProvider;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.*;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Optional;

@Component
@RequiredArgsConstructor
public class JwtValidationFilter implements GlobalFilter {

    private final JwtProvider jwtProvider;
    private final ObjectProvider<AuthClient> authClientProvider;

    // 인증 제외(Path 화이트리스트)
    private static final List<String> WHITE_LIST = List.of(
            "/api/auth", "/api/login", "/api/signup", "/static", "/actuator", "/api/books", "/api/order/guest", "/api/guests",
            "/api/members/check-status",
            "/api/members/inactive/verification",
            "/api/members/inactive/verification/verify",
            "/books/search",
            "/api/payments"
    );

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        // 화이트 리스트 경로는 패스
        if(isExcludedPath(exchange.getRequest().getPath().value())) {
            return chain.filter(exchange);
        }

        // 토큰 추출 - Authorization 헤더 읽고 -> 없으면 쿠키
        String accessToken = resolveToken(exchange);
        if(accessToken == null) {
            return unauthorized(exchange, "토큰이 없습니다.");
        }

        // 토큰 검증
        try {
            jwtProvider.validateToken(accessToken);
        } catch (ExpiredJwtException e) {
            // 만료된 경우 -> 재발급 시도
            return refreshAndContinue(exchange, chain);
        } catch (JwtException e) {
            return unauthorized(exchange, "위조된 토큰입니다.");
        }

        // 4. 정상 토큰이면 클레임 추출해서 내부 헤더 주입
        return continueWithUserHeaders(accessToken, exchange, chain);
    }

    private Mono<Void> refreshAndContinue(ServerWebExchange exchange, GatewayFilterChain chain) {
        AuthClient authClient = authClientProvider.getObject();

        // (1) RefreshToken 추출 (쿠키나 헤더 등)
        String refreshToken = Optional.ofNullable(exchange.getRequest().getCookies().getFirst("REFRESH_TOKEN"))
                .map(HttpCookie::getValue)
                .orElse(null);

        if (refreshToken == null) {
            return unauthorized(exchange, "리프레시 토큰이 없습니다.");
        }

        TokenRefreshRequest req = new TokenRefreshRequest(refreshToken);

        return Mono.fromCallable(() -> authClient.refresh(req))
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(tr -> onRefreshSuccess(tr, exchange, chain))
                .onErrorResume(e -> unauthorized(exchange, "토큰 재발급 실패: " + e.getMessage()));
    }

    private Mono<Void> onRefreshSuccess(TokenResponse tr, ServerWebExchange exchange, GatewayFilterChain chain) {

        ResponseCookie cookie = ResponseCookie.from("ACCESS_TOKEN", tr.getAccessToken())
                .httpOnly(true)
                .secure(true)
                .path("/")
                .maxAge(Duration.ofSeconds(tr.getExpiresIn()))
                .build();
        exchange.getResponse().addCookie(cookie);

        return continueWithUserHeaders(tr.getAccessToken(), exchange, chain);
    }

    private Mono<Void> continueWithUserHeaders(String accessToken, ServerWebExchange exchange, GatewayFilterChain chain) {

        Long userId = jwtProvider.getUserIdFromToken(accessToken);
        String role   = jwtProvider.getRoleFromToken(accessToken);

        ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                .header("X-USER-ID",   String.valueOf(userId))
                .header("X-USER-ROLE", role)
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
