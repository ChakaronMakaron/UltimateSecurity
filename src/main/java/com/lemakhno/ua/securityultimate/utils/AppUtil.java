package com.lemakhno.ua.securityultimate.utils;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import com.lemakhno.ua.securityultimate.entity.RoleEntity;

public class AppUtil {
    
    public static Collection<? extends GrantedAuthority> mapRolesToAuthorities(List<RoleEntity> roles) {

        return roles.stream().map(role -> new SimpleGrantedAuthority(role.getName())).collect(Collectors.toList());
    }

    public static String authoritiesListToString(Collection<? extends GrantedAuthority> authoritiesList) {

        List<String> authorities = authoritiesList.stream().map(authority -> authority.getAuthority()).collect(Collectors.toList());

        return String.join(" ", authorities);
    }
}


