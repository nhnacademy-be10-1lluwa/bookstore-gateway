package com.nhnacademy.illuwa.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class TokenValidationResult {
    private boolean valid;
    private boolean expired;
    private boolean blacklisted;
    private Long userId;
    private String role;
    private String reason;

    public static TokenValidationResult success(Long userId, String role) {
        return new TokenValidationResult(true, false, false, userId, role, null);
    }

    public static TokenValidationResult expired() {
        return new TokenValidationResult(false, true, false, null, null, "EXPIRED_TOKEN");
    }

    public static TokenValidationResult blacklisted() {
        return new TokenValidationResult(false, false, true, null, null, "BLACKLISTED_TOKEN");
    }

    public static TokenValidationResult invalid() {
        return new TokenValidationResult(false, false, false, null, null, "INVALID_TOKEN");
    }
}