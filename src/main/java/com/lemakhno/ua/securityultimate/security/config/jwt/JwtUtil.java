package com.lemakhno.ua.securityultimate.security.config.jwt;

import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.lemakhno.ua.securityultimate.security.config.SecurityConstants;

public class JwtUtil {

    public static String generateToken(User user) {

        String accessToken = JWT.create()
        .withSubject(user.getUsername())
        .withExpiresAt(new Date(System.currentTimeMillis() + SecurityConstants.EXPIRATION_TIME))
        .withClaim("roles", authoritiesCollectionToRolesList(user.getAuthorities()))
        .sign(SecurityConstants.ALGORITHM);

        return accessToken;
    }

    public static String generateToken(String username, List<String> roles) {

        String accessToken = JWT.create()
        .withSubject(username)
        .withExpiresAt(new Date(System.currentTimeMillis() + SecurityConstants.EXPIRATION_TIME))
        .withClaim("roles", roles)
        .sign(SecurityConstants.ALGORITHM);

        return accessToken;
    }

    public static String generateRefreshToken(User user) {

        String refreshToken = JWT.create()
        .withSubject(user.getUsername())
        .withExpiresAt(new Date(System.currentTimeMillis() + SecurityConstants.EXPIRATION_TIME * SecurityConstants.REFRESH_TOKEN_MULTIPLIER))
        .withClaim("roles", authoritiesCollectionToRolesList(user.getAuthorities()))
        .sign(SecurityConstants.ALGORITHM);

        return refreshToken;
    }

    public static String generateRefreshToken(String username, List<String> roles) {

        String refreshToken = JWT.create()
        .withSubject(username)
        .withExpiresAt(new Date(System.currentTimeMillis() + SecurityConstants.EXPIRATION_TIME * SecurityConstants.REFRESH_TOKEN_MULTIPLIER))
        .withClaim("roles", roles)
        .sign(SecurityConstants.ALGORITHM);

        return refreshToken;
    }

    public static DecodedJWT getDecodedJwt(String accessToken) {

        JWTVerifier verifier = JWT.require(SecurityConstants.ALGORITHM).build();

        return verifier.verify(accessToken);
    }

    public static Collection<SimpleGrantedAuthority> rolesListToAuthoritiesCollection(List<String> roles) {
        return roles.stream().map(role -> new SimpleGrantedAuthority(role)).collect(Collectors.toList());
    }

    public static List<String> authoritiesCollectionToRolesList(Collection<? extends GrantedAuthority> authorities) {
        return authorities.stream().map(authority -> authority.getAuthority()).collect(Collectors.toList());
    }

    public static Collection<SimpleGrantedAuthority> rolesArrayToAuthoritiesCollection(String[] rolesArr) {
        return Arrays.stream(rolesArr).map(role -> new SimpleGrantedAuthority(role)).collect(Collectors.toList());
    }

    public static List<String> rolesArrayToRolesList(String[] rolesArr) {
        return Arrays.stream(rolesArr).collect(Collectors.toList());
    }
}


