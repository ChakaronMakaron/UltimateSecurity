package com.lemakhno.ua.securityultimate.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.lemakhno.ua.securityultimate.entity.RoleEntity;

public interface RoleRepository extends JpaRepository<RoleEntity, Long> {

    public RoleEntity findByName(String roleName);
}
