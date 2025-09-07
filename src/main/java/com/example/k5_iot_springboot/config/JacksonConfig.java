package com.example.k5_iot_springboot.config; // 패키지 선언

import com.fasterxml.jackson.databind.ObjectMapper; // Jackson의 ObjectMapper 클래스 임포트
import com.fasterxml.jackson.databind.SerializationFeature; // 직렬화 기능 관련 클래스 임포트
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule; // Java 8 날짜/시간 지원 모듈 임포트
import org.springframework.context.annotation.Bean; //  @Bean 어노테이션 임포트
import org.springframework.context.annotation.Configuration; // @Configuration 어노테이션 임포트

/**
 * Jackson에 JavaTimeModule 등록 + 타임 스탬프(숫자) 대신 ISO-8601 문자열로 출력
 * : LocalDateTime 등의 직렬화/역직렬화가 자연스럽게 동작
 * */
@Configuration // 설정 클래스 선언
public class JacksonConfig { // Jackson 설정 클래스
    // ObjectMapper 빈 등록
    @Bean
    public ObjectMapper objectMapper() { // ObjectMapper 클래스: 직렬화/역직렬화 담당
        ObjectMapper om = new ObjectMapper(); // ObjectMapper 객체 생성
        om.registerModule(new JavaTimeModule()); // Java 8 날짜/시간 지원

        // 숫자 타임스탬프 출력 비활성화: "yyyy-MM-dd'T'HH:mm:ss"형태의 문자열로 (ISO-8601)
        om.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

        return om; // 빈으로 등록된 ObjectMapper 반환
    }
}