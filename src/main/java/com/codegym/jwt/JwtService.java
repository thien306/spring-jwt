package com.codegym.jwt;

import com.codegym.security.UserPrinciple;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import java.security.Key;
import java.util.Date;

@Service
public class JwtService {

    private static final String SECRET_KEY = "123456789987654321123456789987654321123456789"; // khóa bí mật dùng để ký và xác thực JWT
    private static final long EXPIRE_TIME = 86400000L; // Thời gian hết hạn của JWT

    private Key getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String generateTokenLogin(Authentication authentication) {
        UserPrinciple userPrincipal = (UserPrinciple) authentication.getPrincipal(); // Lấy thông tin người dùng

        return Jwts.builder()
                .setSubject((userPrincipal.getUsername()))
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRE_TIME))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public Boolean validateJwtToken(String authToken) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(authToken);
            return true;
        } catch (MalformedJwtException e) {
            System.out.println("Mã thông báo JWT không hợp lệ -> Message: " + e.getMessage());
        } catch (ExpiredJwtException e) {
            System.out.println("Mã thông báo JWT đã hết hạn -> Message: " + e.getMessage());
        } catch (UnsupportedJwtException e) {
            System.out.println("Mã thông báo JWT không được hỗ trợ -> Message: " + e.getMessage());
        } catch (IllegalArgumentException e) {
            System.out.println("Chuỗi xác nhận JWT trống -> Message: " + e.getMessage());
        }
        return false;
    }

    public String getUsernameFromJwtToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }
}
