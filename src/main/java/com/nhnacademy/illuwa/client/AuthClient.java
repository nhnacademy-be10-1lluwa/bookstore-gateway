package com.nhnacademy.illuwa.client;


import com.nhnacademy.illuwa.dto.TokenRefreshRequest;
import com.nhnacademy.illuwa.dto.TokenResponse;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@FeignClient(name = "auth-service")
public interface AuthClient {
    @PostMapping("/auth/refresh")
    TokenResponse refresh(@RequestBody TokenRefreshRequest body);
}
