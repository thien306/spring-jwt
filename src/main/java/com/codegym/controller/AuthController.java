package com.codegym.controller;

import com.codegym.configuration.service.JwtResponse;
import com.codegym.configuration.service.JwtService;
import com.codegym.configuration.service.UserService;
import com.codegym.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RestController
@CrossOrigin("*")
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private UserService userService;


    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody User user) {

        // xác thực người dùng bằng tên người dùng và mật khẩu
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword()));


        // giúp Spring Security biết rằng người dùng đã được xác thực
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // tạo JWT dựa trên thông tin xác thực
        String jwt =jwtService.generateTokenLogin(authentication);

        // chứa thông tin chi tiết về người dùng đã xác thực.
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        User currentUser = userService.findByUsername(user.getUsername());

        return ResponseEntity.ok(new JwtResponse(currentUser.getId(), jwt, userDetails.getUsername(), userDetails.getUsername(), userDetails.getAuthorities()));

    }
}
