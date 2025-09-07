package com.example.k5_iot_springboot.config; // 패키지 선언

import jakarta.annotation.PostConstruct; // @PostConstruct 어노테이션 임포트
import org.springframework.context.annotation.Configuration; // 설정 클래스 선언을 위한 어노테이션 임포트

import java.util.TimeZone; // 타임존 설정을 위한 TimeZone 클래스 임포트

/**
 * 애플리케이션의 "기본 타임존"을 UTC로 고정
 * - JPA Auditing이 LocalDateTime.now() 등을 사용할 때 기준
 * - DB에는 타임존 정보가 없는 DATETIME 저장
 *      : UTC 기준 일괄 저장이 안전
 * */
@Configuration // 설정 파일을 만들기 위한 어노테이션 (Bean 등록)
public class TimeConfig { // 시간 설정 클래스
    @PostConstruct // 종속성 주입이 완료된 후 실행되어야 하는 메서드에 사용(설정값 세팅, 외부 API 초기 연결 등)
    public void setDefaultTimeZone() {
        // 서버 JVM 기본 타임존을 UTC로 고정
        TimeZone.setDefault(TimeZone.getTimeZone("UTC")); // UTC(협정 세계시)로 타임존 설정
    }
}