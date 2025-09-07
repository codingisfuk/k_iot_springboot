package com.example.k5_iot_springboot.security.util; // 패키지 선언

import com.example.k5_iot_springboot.security.UserPrincipal; // UserPrincipal 클래스 임포트
import org.springframework.security.access.AccessDeniedException; // 접근 거부 예외 클래스 임포트

public class PrincipalUtils { // Principal 관련 유틸리티 클래스
    private PrincipalUtils() {} // 인스턴스화 방지 (유틸리티 클래스이므로)

    /** UserPrincipal 전용 검증 */
    public static void requiredActive(UserPrincipal principal)  { // 활성화된 사용자 검증 메서드
        if (principal == null) {  // null 체크
            throw new AccessDeniedException("인증 필요"); // 인증 필요 예외 발생
        }
        if (!principal.isAccountNonLocked() || !principal.isEnabled() || !principal.isAccountNonExpired()) {    // 계정 상태 체크
            throw new AccessDeniedException("비활성화 된 계정"); // 비활성화 계정 예외 발생
        }
    }
}