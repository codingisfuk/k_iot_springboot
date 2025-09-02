package com.example.k5_iot_springboot.service.impl;

import com.example.k5_iot_springboot.dto.I_Order.request.StockRequest;
import com.example.k5_iot_springboot.dto.I_Order.response.StockResponse;
import com.example.k5_iot_springboot.dto.ResponseDto;
import com.example.k5_iot_springboot.entity.I_Stock;
import com.example.k5_iot_springboot.repository.I_StockRepository;
import com.example.k5_iot_springboot.security.UserPrincipal;
import com.example.k5_iot_springboot.service.I_StockService;
import jakarta.persistence.EntityNotFoundException;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class I_StockServiceImpl implements I_StockService {
    private final I_StockRepository stockRepository;


    @Override
    public ResponseDto<StockResponse.Response> adjust(UserPrincipal userPrincipal, StockRequest.@Valid StockAdjust req) {
        // 재고 증감 (delta)
        // : delta 값이 양수 - 입고/반품
        //         값이 음수 - 출고/차감

        StockResponse.Response data = null; // 실제 ResponseDto 내부에서 전달될 data 타입을 초기화

        I_Stock stock = stockRepository.findByProductIdForUpdate(req.productId())
                .orElseThrow(() -> new EntityNotFoundException("재고 정보를 찾을 수 없습니다, productId=" + req.productId()));

        int newQuantity = stock.getQuantity() + req.delta();

        if (newQuantity < 0) throw new IllegalArgumentException("재고가 부족합니다");

        stock.setQuantity(newQuantity);

        data = new StockResponse.Response(
                stock.getProduct().getId(),
                stock.getQuantity()
        );

        return ResponseDto.setSuccess("재고가 성공적으로 증감되었습니다.",data);

    }

    @Override
    public ResponseDto<StockResponse.Response> set(UserPrincipal userPrincipal, StockRequest.@Valid StockSet req) {
        return null;
    }

    @Override
    public ResponseDto<StockResponse.Response> get(Long productId) {
        return null;
    }
}
