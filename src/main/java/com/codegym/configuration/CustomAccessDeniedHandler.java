package com.codegym.configuration;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import java.io.IOException;

// xử lý các trường hợp khi một người dùng cố gắng truy cập vào một tài nguyên mà họ không được phép truy cập

public class CustomAccessDeniedHandler implements AccessDeniedHandler {

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException)
            throws IOException, ServletException {
        response.setStatus(HttpServletResponse.SC_FORBIDDEN); // phản hồi là 403, tức là "Forbidden" (Bị cấm)
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write("{\"error\": \"Truy cập bị từ chối!\"}");
    }
}

