package com.lemakhno.ua.securityultimate.controller;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.core.exc.StreamWriteException;
import com.fasterxml.jackson.databind.DatabindException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.lemakhno.ua.securityultimate.entity.RoleEntity;
import com.lemakhno.ua.securityultimate.entity.UserEntity;
import com.lemakhno.ua.securityultimate.response.ResponseMessage;
import com.lemakhno.ua.securityultimate.security.config.SecurityConstants;
import com.lemakhno.ua.securityultimate.security.config.jwt.JwtUtil;
import com.lemakhno.ua.securityultimate.service.UserService;

@RestController
@RequestMapping("/api")
public class RefreshTokenController {

    @Autowired
    ObjectMapper objectMapper;
    
    @Autowired
    private UserService userService;

    @GetMapping("/user")
    public ResponseEntity<List<UserEntity>> getAllUsers() {
        
        return ResponseEntity.ok(userService.getAllUsers());
    }

    @PostMapping("/user")
    public UserEntity saveUser(@RequestBody UserEntity user) {
        return userService.saveNewUser(user);
    }

    @PostMapping("/role")
    public RoleEntity saveRole(@RequestBody RoleEntity role) {
        return userService.saveNewRole(role);
    }

    @PostMapping("/user/newRole")
    public String addNewRoleToUser(String mock) {
        return "OK";
    }
    
    @GetMapping("user/getRefreshToken")
    public void getRefreshToken(HttpServletRequest request, HttpServletResponse response) throws StreamWriteException, DatabindException, IOException {

            String authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

            // If authorization header is missing or malformed
            if (authorizationHeader == null || !authorizationHeader.startsWith(SecurityConstants.TOKEN_PREFIX)) {
                System.out.println(">>> ATTEMPTING TO GET REFRESH TOKEN WITHOUT AUTHENTICATION HEADER");
    
                Map<String, Object> responseBody = new HashMap<>();
                responseBody.put("status", HttpStatus.UNAUTHORIZED.value());
                responseBody.put("message", ResponseMessage.NO_AUTHENTICATION_PROVIDED.toString());
    
                response.setStatus(HttpStatus.UNAUTHORIZED.value());
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
    
                objectMapper.writeValue(response.getOutputStream(), responseBody);
    
                return;
            }

            try {

                String accessToken = authorizationHeader.substring(SecurityConstants.TOKEN_PREFIX.length());
                
                JWTVerifier verifier = JWT.require(SecurityConstants.ALGORITHM).build();

                DecodedJWT decodedJWT = verifier.verify(accessToken); // <- Throws Runtime JWTVerificationException

                String username = decodedJWT.getSubject();
                List<String> rolesAsList = decodedJWT.getClaim("roles").asList(String.class);

                String newAccessToken = JwtUtil.generateToken(username, rolesAsList);

                String newRefreshToken = JwtUtil.generateRefreshToken(username, rolesAsList);

                Map<String, String> responseBody = new HashMap<>();
                responseBody.put("accessToken", newAccessToken);
                responseBody.put("refreshToken", newRefreshToken);

                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                response.setStatus(200);

                objectMapper.writeValue(response.getOutputStream(), responseBody);
                
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


