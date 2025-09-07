package com.example.k5_iot_springboot.config; // 패키지 선언

import org.springframework.context.annotation.Configuration; // @Configuration 어노테이션 임포트
import org.springframework.data.jpa.repository.config.EnableJpaAuditing; // @EnableJpaAuditing 어노테이션 임포트

/**
 * JPA Auditing을 전역 설정
 * - @CreatedDate, @LastModifiedDate 등이 동작하려면 필수!
 * */
@Configuration // 전역 설정
@EnableJpaAuditing // JpaAuditing 사용 설정
public class JpaAuditingConfig { // JPA Auditing 설정 클래스
}