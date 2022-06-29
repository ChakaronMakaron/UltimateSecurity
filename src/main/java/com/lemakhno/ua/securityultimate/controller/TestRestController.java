package com.lemakhno.ua.securityultimate.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestRestController {
    
    @GetMapping("/admin")
    public String getAdminResource() {
        return "Hello admin";
    }

    @GetMapping("/user")
    public String getUserResource() {
        return "Hello lox";
    }

    @GetMapping("/")
    public String getUnprotectedResource() {
        return "Hello dis is for everivan";
    }

    @GetMapping("/authorized")
    public String getResourceForAuthorized() {
        return "Hello dis is for just authorized";
    }
}


