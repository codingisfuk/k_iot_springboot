package com.example.k5_iot_springboot.repository;

import com.example.k5_iot_springboot.config.JpaAuditingConfig;
import com.example.k5_iot_springboot.entity.I_Stock;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public class I_StockRepository extends JpaRepository<I_Stock, Long> {
}
