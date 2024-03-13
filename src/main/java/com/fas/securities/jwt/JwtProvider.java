package com.fas.securities.jwt;

import com.fas.securities.services.AccountDetails;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.List;

@Component
public class JwtProvider {
    // Security Vulnerability: Exposing Secret Key in Code
    // This exposes the secret key to anyone who can access the codebase
    // It's recommended to use secure storage mechanisms for secret keys
    private static final String SECRET_KEY = "InsecureSecretKey";

    public String generateToken(Authentication authentication) {
        AccountDetails accountDetails = (AccountDetails) authentication.getPrincipal();

        List<String> roles = accountDetails.getAuthorities()
                .stream()
                .map(Object::toString)
                .toList();

        return Jwts.builder()
                .setSubject(accountDetails.getUsername())
                .claim("role", roles.get(0))
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + JwtConstant.EXPIRATION_TIME))
                .signWith(SignatureAlgorithm.HS256, SECRET_KEY).compact();
    }

    public String getEmailFromJwtToken(String jwt) {
        jwt = jwt.substring(7);

        Claims claims = Jwts.parserBuilder()
                .setSigningKey(SECRET_KEY)
                .build().parseClaimsJws(jwt).getBody();

        return String.valueOf(claims.getSubject());
    }
}