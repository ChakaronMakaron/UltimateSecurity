package com.lemakhno.ua.securityultimate.service;

import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.lemakhno.ua.securityultimate.entity.RoleEntity;
import com.lemakhno.ua.securityultimate.entity.UserEntity;
import com.lemakhno.ua.securityultimate.repository.RoleRepository;
import com.lemakhno.ua.securityultimate.repository.UserRepository;
import com.lemakhno.ua.securityultimate.utils.AppUtil;

@Service
@Transactional
public class UserServiceImpl implements UserService {

    Logger logger = Logger.getLogger(this.getClass().getName());

    {
        logger.setLevel(Level.INFO);
    }

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        
        // Username -> Email
        UserEntity storedUser = userRepository.findByEmail(email);

        if (storedUser == null) {
            throw new UsernameNotFoundException("User not found: " + email);
        }

        UserDetails userDetails = new User(
                                storedUser.getEmail(),
                                storedUser.getEncryptedPassword(),
                                AppUtil.mapRolesToAuthorities(storedUser.getRoles())
                                        );

        return userDetails;
    }

    @Override
    public UserEntity saveNewUser(UserEntity user) {

        logger.info("####################");
        logger.info(">>> Saving new User |" + user);
        logger.info("####################");

        String forSureEncryptedPassword = passwordEncoder.encode(user.getEncryptedPassword());
        user.setEncryptedPassword(forSureEncryptedPassword);

        return userRepository.save(user);
    }

    @Override
    public RoleEntity saveNewRole(RoleEntity role) {
        return roleRepository.save(role);
    }

    @Override
    public void addRoleToUser(String username, String roleName) {

        logger.info("####################");
        logger.info(">>> Adding new Role |" + roleName + "| to User |" + username);
        logger.info("####################");

        UserEntity user = userRepository.findByEmail(username);
        RoleEntity role = roleRepository.findByName(roleName);

        user.addRole(role);
    }

    @Override
    public UserEntity getUser(String username) {
        return userRepository.findByEmail(username);
    }

    @Override
    public List<UserEntity> getAllUsers() {
        return userRepository.findAll();
    }
}


