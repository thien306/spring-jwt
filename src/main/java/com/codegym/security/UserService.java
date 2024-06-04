package com.codegym.security;

import com.codegym.model.User;

import com.codegym.repository.IUserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

@Service
public class UserService implements UserDetailsService {

    @Autowired
    private IUserRepository userRepository;

    public User findByUsername(String name) {
        return userRepository.findByUsername(name);
    }

    public UserDetails loadUserByUsername(String username) {
        return UserPrinciple.build(userRepository.findByUsername(username));
    }



}
