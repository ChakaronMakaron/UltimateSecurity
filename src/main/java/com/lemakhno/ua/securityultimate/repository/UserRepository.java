package com.lemakhno.ua.securityultimate.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.lemakhno.ua.securityultimate.entity.UserEntity;

@Repository
public interface UserRepository extends JpaRepository<UserEntity, Integer> {
    
    public UserEntity findByEmail(String email);
}
