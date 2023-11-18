package com.qortmdcks.jwt5.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.function.Function;

// @Service 어노테이션은 이 클래스를 서비스 계층의 컴포넌트로 정의하며,
// 스프링 컨테이너에서 관리될 수 있게 합니다.
@Service
public class JwtService {

    // JWT 시크릿 키와 만료 시간을 application.properties 파일로부터 주입받습니다.
    @Value("${application.security.jwt.secret-key}")
    private String secretkey;
    @Value("${application.security.jwt.expiration}")
    private Long jwtExpiration;

    // 토큰에서 사용자 이름(여기서는 subject)을 추출하는 메소드입니다.
    public String extractUsername(String token){
        return extractClaim(token, Claims::getSubject);
    }

    // 토큰에서 특정 클레임을 추출하는 범용 메소드입니다.
    // Function 인터페이스를 사용하여 추출할 클레임 타입을 유연하게 지정할 수 있습니다.
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver){
        final Claims claims = extactAllClaims(token);
        return claimsResolver.apply(claims);
    }

    // 토큰에서 모든 클레임을 추출하는 메소드입니다.
    // Jwts 라이브러리를 사용하여 파싱하고, 시크릿 키를 사용하여 서명을 검증합니다.
    public Claims extactAllClaims(String token){
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    // 시크릿 키를 바이트 배열로 디코딩하고, HMAC SHA 알고리즘을 사용하여 Key 객체를 생성합니다.
    private Key getSignKey(){
        byte[] KeyBytes = Decoders.BASE64.decode(secretkey);
        return Keys.hmacShaKeyFor(KeyBytes);
    }
}
