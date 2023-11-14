package com.demo.spring_jwt.config;

import java.security.Key;
import java.sql.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Value;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {

	@Value("${application.security.jwt.secret-key}")
    private String secretKey;

    // Method to extract the username from a JWT token.
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    // Method to extract a specific claim (payload information) from a JWT token.
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    // Private method to extract all claims (payload) from a JWT token.
    private Claims extractAllClaims(String token) {
        return Jwts
            .parserBuilder()
            .setSigningKey(getSignInKey())
            .build()
            .parseClaimsJws(token)
            .getBody();
    }

    // Method to generate a JWT token for a user.
    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    // Method to generate a JWT token with extra claims for a user.
    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return Jwts
            .builder()
            .setClaims(extraClaims)
            .setSubject(userDetails.getUsername())
            .setIssuedAt(new Date(System.currentTimeMillis()))
            .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))  // Token expiration time (1 day)
            .signWith(getSignInKey(), SignatureAlgorithm.HS256)
            .compact();
    }

    // Method to check if a JWT token is valid for a given user.
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    // Private method to check if a JWT token has expired.
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date(System.currentTimeMillis()));
    }

    // Private method to extract the expiration date from a JWT token.
    private Date extractExpiration(String token) {
        return (Date) extractClaim(token, Claims::getExpiration);
    }

    // Private method to get the signing key used for JWT validation.
    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
