package com.lemakhno.ua.securityultimate.beans;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.fasterxml.jackson.databind.ObjectMapper;

@Configuration
public class AppBeans {
    
    @Bean
    public ObjectMapper objectMapper() {

        return new ObjectMapper();
    }
}


