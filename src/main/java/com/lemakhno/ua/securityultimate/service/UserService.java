package com.lemakhno.ua.securityultimate.service;

import java.util.List;

import org.springframework.security.core.userdetails.UserDetailsService;

import com.lemakhno.ua.securityultimate.entity.RoleEntity;
import com.lemakhno.ua.securityultimate.entity.UserEntity;

public interface UserService extends UserDetailsService {

    public UserEntity saveNewUser(UserEntity user);
    public RoleEntity saveNewRole(RoleEntity role);
    public void addRoleToUser(String username, String roleName);
    public UserEntity getUser(String username);
    public List<UserEntity> getAllUsers();
}


