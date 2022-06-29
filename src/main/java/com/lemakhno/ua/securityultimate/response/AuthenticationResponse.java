package com.lemakhno.ua.securityultimate.response;

public class AuthenticationResponse {
    
    private String acessToken;

    public AuthenticationResponse() {}

    public AuthenticationResponse(String acessToken) {
        this.acessToken = acessToken;
    }

    public String getAcessToken() {
        return acessToken;
    }

    public void setAcessToken(String acessToken) {
        this.acessToken = acessToken;
    }

}


