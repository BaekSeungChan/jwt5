package com.qortmdcks.jwt5.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

// @Component 어노테이션은 이 클래스를 스프링 컴포넌트로 표시하여 스프링 의존성 주입에서 발견될 수 있게 합니다.
@Component

// @RequiredArgsConstructor는 필요한 처리를 요하는 모든 필드에 대해 한 개의 파라미터를 갖는 생성자를 생성합니다.
// 이 경우, JwtService에 대한 생성자를 생성합니다.
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    // JwtService 의존성 주입.
    // JwtService는 JWT 작업을 처리하는 사용자 정의 서비스로 추정됩니다.
    private final JwtService jwtService;

    // OncePerRequestFilter에서 doFilterInternal 메소드를 오버라이드합니다.
    // 이 메소드는 필터링 로직을 수행하기 위해 요청당 한 번 호출됩니다.
    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain)
            throws ServletException, IOException {

        // 요청에서 'Authorization' 헤더를 검색합니다.
        final String authHeader = request.getHeader("Authorization");

        // JWT 토큰과 사용자 이메일을 위한 변수 초기화.
        final String jwt;
        final String userEmail;

        // 'Authorization' 헤더가 null이거나 "Bearer "로 시작하지 않는지 확인합니다.
        // 이는 HTTP 헤더에서 JWT를 전송하는 표준 방식입니다.
        if(authHeader == null || !authHeader.startsWith("Bearer ")){
            // 조건이 참이면 JWT 처리 없이 필터 체인을 계속 진행합니다.
            filterChain.doFilter(request, response);
            return;
        }

        // 'Authorization' 헤더에서 "Bearer " 접두사를 제거하여 JWT 토큰을 추출합니다.
        jwt = authHeader.substring(7);

        // JwtService를 사용하여 JWT 토큰에서 사용자 이름(이 경우 이메일)을 추출합니다.
        userEmail = jwtService.extractUsername(jwt);

        // 여기에 일반적으로 추출된 사용자 정보를 인증하고 보안 컨텍스트를 설정하는 추가 로직이 있어야 합니다만,
        // 이 코드 조각에서는 구현되지 않았습니다.
    }
}
