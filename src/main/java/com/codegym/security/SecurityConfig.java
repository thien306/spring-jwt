package com.codegym.security;

import com.codegym.configuration.CustomAccessDeniedHandler;
import com.codegym.configuration.RestAuthenticationEntryPoint;
import com.codegym.jwt.JwtAuthenticationTokenFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Autowired
    private UserService userService;

    // Xử lý xác thực JWT, kiểm tra JWT trong mỗi yêu cầu và thiết lập ngữ cảnh bảo mật nếu JWT hợp lệ
    @Bean
    public JwtAuthenticationTokenFilter jwtAuthenticationTokenFilter() {
        return new JwtAuthenticationTokenFilter();
    }

    // Quản lý quá trình xác thực
    @Bean(BeanIds.AUTHENTICATION_MANAGER)
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    // Xử lý các yêu cầu chưa được xác thực, trả về mã trạng thái 401
    @Bean
    public RestAuthenticationEntryPoint restAuthenticationEntryPoint() {
        return new RestAuthenticationEntryPoint();
    }

    // Xử lý các yêu cầu bị từ chối truy cập, trả về mã trạng thái 403
    @Bean
    public CustomAccessDeniedHandler customAccessDeniedHandler() {
        return new CustomAccessDeniedHandler();
    }

    // Thuật toán mã hóa mật khẩu an toàn
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(10);
    }

    // Xác thực người dùng bằng cách sử dụng dịch vụ người dùng (userService) và bộ mã hóa mật khẩu (passwordEncoder)
    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userService);
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        return authenticationProvider;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http.csrf(AbstractHttpConfigurer::disable)
                .addFilterBefore(jwtAuthenticationTokenFilter(), UsernamePasswordAuthenticationFilter.class)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                        // Cho phép tất cả các yêu cầu đến đường dẫn /api/auth/login mà không cần xác thực
                        .requestMatchers("/api/auth/login**").permitAll()
                        // Yêu cầu xác thực cho các yêu cầu GET đến đường dẫn /api/customers
                        .requestMatchers(HttpMethod.GET, "/api/customers**").authenticated()
                        // Yêu cầu quyền ROLE_ADMIN cho các yêu cầu PUT, POST, DELETE đến đường dẫn /api/customers
                        .requestMatchers(HttpMethod.PUT, "/api/customers**").hasAnyAuthority("ROLE_ADMIN")
                        .requestMatchers(HttpMethod.POST, "/api/customers**").hasAnyAuthority("ROLE_ADMIN")
                        .requestMatchers(HttpMethod.DELETE, "/api/customers**").hasAnyAuthority("ROLE_ADMIN")
                )
                .exceptionHandling(customizer -> customizer
                        .authenticationEntryPoint(restAuthenticationEntryPoint())
                        .accessDeniedHandler(customAccessDeniedHandler())
                )
                .sessionManagement(sess -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .httpBasic(Customizer.withDefaults())
                .build();
    }
}
