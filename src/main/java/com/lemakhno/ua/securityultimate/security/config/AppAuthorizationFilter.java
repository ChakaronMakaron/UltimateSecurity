package com.lemakhno.ua.securityultimate.security.config;

import java.io.IOException;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.lemakhno.ua.securityultimate.response.ResponseMessage;
import com.lemakhno.ua.securityultimate.security.config.jwt.JwtUtil;

@Component
public class AppAuthorizationFilter extends OncePerRequestFilter {

    @Autowired
    private ObjectMapper objectMapper;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String requestServletPath = request.getServletPath();

        // If we are LOGGING IN or getting REFRESH TOKEN
        // then we skip this filter
        if (requestServletPath.equals(SecurityConstants.LOGIN_URL) || requestServletPath.equals(SecurityConstants.REFRESH_TOKEN_URL)) {
            System.out.println(">>> LOGIN OR REFRESH TOKEN");
            filterChain.doFilter(request, response);
            return;
        }

        String authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        // If authorization header is missing or malformed
        if (authorizationHeader == null || !authorizationHeader.startsWith(SecurityConstants.TOKEN_PREFIX)) {
            System.out.println(">>> PROCEEDED WITHOUT AUTH");
            filterChain.doFilter(request, response);
            return;
        }

        try {

            String accessToken = authorizationHeader.substring(SecurityConstants.TOKEN_PREFIX.length());

            JWTVerifier verifier = JWT.require(SecurityConstants.ALGORITHM).build();

            DecodedJWT decodedJWT = verifier.verify(accessToken); // <- Throws Runtime JWTVerificationException

            String username = decodedJWT.getSubject();
            List<String> roles = decodedJWT.getClaim("roles").asList(String.class);

            Collection<SimpleGrantedAuthority> authorities = JwtUtil.rolesListToAuthoritiesCollection(roles);

            UsernamePasswordAuthenticationToken authentication =
                            new UsernamePasswordAuthenticationToken(username, null, authorities);

            SecurityContextHolder.getContext().setAuthentication(authentication);
            System.out.println(authentication);
            filterChain.doFilter(request, response);
            
        } catch (JWTVerificationException e) {

            String message = e.getMessage();
            System.out.println(message);

            String responseMessage = null;

            if (message.startsWith("The Token has expired")) {
                responseMessage = ResponseMessage.EXPIRED_TOKEN.toString();
            } else {
                responseMessage = ResponseMessage.INVALID_TOKEN.toString();
            }

            Map<String, Object> responseBody = new HashMap<>();
            responseBody.put("status", HttpStatus.UNAUTHORIZED.value());
            responseBody.put("message", responseMessage);

            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);

            objectMapper.writeValue(response.getOutputStream(), responseBody);
        }
    }
    
}


