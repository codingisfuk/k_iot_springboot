package com.example.k5_iot_springboot.dto.I_Order.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public class ProductRequest {
    /** 제품 등록 요청 DTO */
    public record Create(
            String name,
            Integer price
    ) {}

    /** 제품 수정 요청 DTO */
    public record Update(
            String name,
            Integer price
    ) {}

    public static class DetailResponse {
        public DetailResponse(Long id, @NotBlank @Size(max = 100) String name, @NotNull int price) {
        }
    }
}