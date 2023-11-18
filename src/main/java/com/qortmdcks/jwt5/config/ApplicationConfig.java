package com.qortmdcks.jwt5.config;

import com.qortmdcks.jwt5.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserDetailsService;

@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {
    // UserRepository 인스턴스를 주입받습니다.
    // 이는 데이터베이스와의 상호작용을 처리하는 데 사용됩니다.
    private final UserRepository userRepository;

    // UserDetailsService 빈을 정의합니다.
    // 이 서비스는 Spring Security에 사용자 인증을 위한 사용자 세부 정보를 제공합니다.
    @Bean
    public UserDetailsService userDetailsService(){
        // 람다 표현식을 사용하여 UserDetailsService 인터페이스를 구현합니다.
        // username (이 경우 이메일)을 받아 해당하는 사용자를 찾습니다.
        return username ->
                // UserRepository를 사용하여 데이터베이스에서 사용자를 조회합니다.
                userRepository.findByEmail(username)
                        // 사용자가 존재하지 않는 경우 RuntimeException을 발생시킵니다.
                        .orElseThrow(() -> new RuntimeException("User not email"));
    }
}
