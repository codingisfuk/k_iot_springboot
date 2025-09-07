package com.example.k5_iot_springboot.security.util; // 패키지 선언

import com.example.k5_iot_springboot.common.enums.OrderStatus; // 주문 상태 열거형 임포트
import com.example.k5_iot_springboot.entity.H_Article; // 게시글 엔티티 클래스 임포트
import com.example.k5_iot_springboot.repository.H_ArticleRepository; // 게시글 리포지토리 인터페이스 임포트
import com.example.k5_iot_springboot.repository.I_OrderRepository; // 주문 리포지토리 인터페이스 임포트
import com.example.k5_iot_springboot.security.UserPrincipal; // UserPrincipal 클래스 임포트
import lombok.RequiredArgsConstructor; // Lombok 어노테이션 임포트
import org.springframework.security.core.Authentication; // 인증 객체 임포트
import org.springframework.stereotype.Component; // 스프링 컴포넌트 임포트

// cf) 역할 체크 VS 소유자 검사 및 리포지토리 접근 체크
// 1. 역할 체크
//      : @PreAuthorize("hasRole('ADMIN')")만으로 충분!
// 2. 소유자 검사(게시글 작성자만 수정/삭제 가능)
//      , 리포지토리 접근이 필요한 조건(팀원 여부, 프로젝트 멤버십)이 있다면
//      >> 컨트롤러/서비스에 비즈니스 로직을 섞지 않기 위해 빈(Bean)으로 분리 권장!
@Component("authz") // 스프링이 해당 클래스를 관리하도록 지정, 의존성 주입
@RequiredArgsConstructor // final 필드에 대한 생성자 자동 생성 (의존성 주입 편의성 제공)
public class AuthorizationChecker { // 권한 검사기 클래스
    private final H_ArticleRepository articleRepository; // 게시글 리포지토리
    private final I_OrderRepository orderRepository; // 주문 리포지토리

    /** principal(LoginId)이 해당 articledId의 작성자인지 검사 */
    public boolean isArticleAuthor(Long articleId, Authentication principal) { // 게시글 작성자 검사 메서드
        if (principal == null || articleId == null) return false; // null 체크
        String loginId = principal.getName(); // JwtAuthenticationFilter 에서 username으로 주입
        H_Article article = articleRepository.findById(articleId).orElse(null); // articleId로 게시글 조회
        if (article == null) return false; // 게시글이 없으면 false 반환
        return article.getAuthor().getLoginId().equals(loginId); 
        // loginId와 article의 작성자가 일치하면 true 반환, 아닐 경우 false 반환
    }

    /** USER가 본인의 주문 만을 조회/검색할 수 있도록 체크 */
    public boolean isSelf(Long userId, Authentication authentication) { // 본인 검사 메서드
        if (userId == null) return false; // null 체크

        Long me = extractUserId(authentication); // 인증 객체에서 사용자 ID 추출

        return userId.equals(me); // userId와 추출한 사용자 ID가 일치하면 true 반환, 아닐 경우 false 반환
    }

    /** USER가 해당 주문을 취소할 수 있는지 확인 (본인 & pending) */
    public boolean canCancel(Long orderId, Authentication authentication) { // 주문 취소 가능 검사 메서드
        Long me = extractUserId(authentication); // 인증 객체에서 사용자 ID 추출

        return orderRepository.findById(orderId)  // orderId로 주문 조회
                .map(o -> o.getUser().getId().equals(me) // 본인 확인
                        && o.getOrderStatus() == OrderStatus.PENDING) // 주문 상태가 PENDING인지 확인
                .orElse(false); // 주문이 없으면 false 반환
    }

    // == 프로젝트의 Principal 구조에 맞게 사용자 ID 추출 == //
    private Long extractUserId (Authentication authentication) { // 인증 객체에서 사용자 ID 추출 메서드
        if (authentication == null) return null; // null 체크
        Object principal = authentication.getPrincipal(); // 인증 객체에서 principal 추출

        // 1) 커스텀 principal 사용하는 경우
        if (principal instanceof UserPrincipal up) { // 다운캐스팅 시도
            return up.getId(); // UserPrincipal에서 ID 추출하여 반환
        }
        // 2) 다운캐스팅 실패 시 null 반환 - UserPrincipal이 아닐 때 fallback (거의 안 씀)
        return null;
    }
}