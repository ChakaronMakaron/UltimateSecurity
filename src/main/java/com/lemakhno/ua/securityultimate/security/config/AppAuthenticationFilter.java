package com.lemakhno.ua.securityultimate.security.config;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.lemakhno.ua.securityultimate.request.AuthenticationRequest;
import com.lemakhno.ua.securityultimate.response.ResponseMessage;
import com.lemakhno.ua.securityultimate.security.config.jwt.JwtUtil;

@Component
public class AppAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    Logger logger = Logger.getLogger(this.getClass().getName());

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private ObjectMapper objectMapper;

    public AppAuthenticationFilter(AuthenticationManager authenticationManager) {
        setFilterProcessesUrl(SecurityConstants.LOGIN_URL);
        setAuthenticationManager(authenticationManager);
        this.authenticationManager = authenticationManager;
    }

    // {
    //     setFilterProcessesUrl(SecurityConstants.LOGIN_URL);
    // }

    // @Override
    // @Autowired
    // public void setAuthenticationManager(AuthenticationManager authenticationManager) {
    //     super.setAuthenticationManager(authenticationManager);
    // }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        
        System.out.println(">>> ATTEMPTING AUTH");

        try (InputStream requestInputStream = request.getInputStream()) {

            AuthenticationRequest authenticationRequest = objectMapper.readValue(requestInputStream, AuthenticationRequest.class);

            String username = authenticationRequest.getUsername();
            String password = authenticationRequest.getPassword();

            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, password);

            return authenticationManager.authenticate(authenticationToken);

        } catch (IOException e) {
            
            throw new RuntimeException(e.getMessage());
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
            Authentication authentication) throws IOException, ServletException {
        
        User user = (User) authentication.getPrincipal();

        logger.info(">>>" + " Successful authentication, roles: " + user.getAuthorities());

        String accessToken = JwtUtil.generateToken(user);

        String refreshToken = JwtUtil.generateRefreshToken(user);

        Map<String, String> responseBody = new HashMap<>();
        responseBody.put("message", ResponseMessage.SUCCESSFUL_LOGIN.toString());
        responseBody.put("accessToken", accessToken);
        responseBody.put("refreshToken", refreshToken);

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(200);

        objectMapper.writeValue(response.getOutputStream(), responseBody);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException failed) throws IOException, ServletException {

        System.out.println(">>> " + failed.getMessage());

        Map<String, Object> responseBody = new HashMap<>();
        responseBody.put("status", HttpStatus.UNAUTHORIZED.value());
        responseBody.put("message", ResponseMessage.LOGIN_FAIL.toString());

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(401);

        objectMapper.writeValue(response.getOutputStream(), responseBody);
    }

}


