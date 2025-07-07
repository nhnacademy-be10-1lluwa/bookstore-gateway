package com.nhnacademy.illuwa.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class TokenRefreshRequest {
    @NotBlank
    @JsonProperty("refresh_token")   // JSON 필드명 snake_case 유지
    private String refreshToken;
}
