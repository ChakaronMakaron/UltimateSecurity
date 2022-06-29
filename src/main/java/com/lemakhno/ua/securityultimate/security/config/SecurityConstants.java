package com.lemakhno.ua.securityultimate.security.config;

import com.auth0.jwt.algorithms.Algorithm;

public class SecurityConstants {

    public static final Algorithm ALGORITHM = Algorithm.HMAC512(SecurityConstants.TOKEN_SECRET);
    public static final String TOKEN_SECRET = "4CmaTg7HfQ58N4XVinma";
    public static final String TOKEN_PREFIX = "Bearer ";
    public static final String LOGIN_URL = "/api/login";
    public static final String REFRESH_TOKEN_URL = "/api/user/getRefreshToken";
    public static final Long EXPIRATION_TIME = 18000000L;
    public static final Long EXPIRATION_TIME_5 = 5000L;
    public static final Integer REFRESH_TOKEN_MULTIPLIER = 3;
}


