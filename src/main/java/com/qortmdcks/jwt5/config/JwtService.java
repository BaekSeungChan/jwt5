package com.qortmdcks.jwt5.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    // application.properties에서 JWT 시크릿 키와 만료 시간을 주입받습니다.
    @Value("${application.security.jwt.secret-key}")
    private String secretkey;
    @Value("${application.security.jwt.expiration}")
    private Long jwtExpiration;
    @Value("${application.security.jwt.refresh-token.expiration}")
    private Long refreshExpiration;

    // 토큰에서 사용자 이름(subject)을 추출하는 메소드입니다.
    public String extractUsername(String token){
        return extractClaim(token, Claims::getSubject);
    }

    // 토큰에서 특정 클레임을 추출하는 범용 메소드입니다.
    // Function 인터페이스를 사용하여 추출할 클레임의 타입을 유연하게 지정할 수 있습니다.
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver){
        final Claims claims = extactAllClaims(token);
        return claimsResolver.apply(claims);
    }

    // 사용자 세부 정보를 기반으로 JWT 토큰을 생성합니다.
    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(), userDetails);
    }

    // 추가 클레임과 사용자 세부 정보를 기반으로 JWT 토큰을 생성하는 오버로딩된 메소드입니다.
    public String generateToken(
            Map<String, Object> extractClaims,
            UserDetails userDetails
    ){
        return buildToken(new HashMap<>(), userDetails, refreshExpiration);
    }

    // JWT 토큰을 실제로 구성하고 서명하는 메소드입니다.
    // 사용자 세부 정보, 클레임, 만료 시간을 받아 토큰을 생성합니다.
    public String buildToken(
            Map<String, Object> extractClaims,
            UserDetails userDetails,
            long expiration
    ){
        return Jwts
                .builder()
                .setClaims(extractClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSignKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    // 토큰에서 모든 클레임을 추출하는 메소드입니다.
    // Jwts 라이브러리를 사용하여 토큰을 파싱하고, 시크릿 키를 사용하여 서명을 검증합니다.
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
