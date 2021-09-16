package com.example.security.config;

import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity(debug = true)
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final CustomAuthDetail customAuthDetail;

    public SecurityConfig(CustomAuthDetail customAuthDetail) {
        this.customAuthDetail = customAuthDetail;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //super.configure(auth);

        // 임시 사용자 세팅
        auth.inMemoryAuthentication()
                .withUser(User.builder()
                        .username("admin")
                        .password(passwordEncoder().encode("admin"))
                        .roles("ADMIN")
                )
                .withUser(User.builder()
                        .username("user1")
                        .password(passwordEncoder().encode("user1"))
                        .roles("USER")
                )
                .withUser(User.builder()
                        .username("user2")
                        .password(passwordEncoder().encode("user2"))
                        .roles("USER")
                );

    }

    @Bean
    RoleHierarchy roleHierarchy() {
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        roleHierarchy.setHierarchy("ROLE_ADMIN > ROLE_USER");
        return roleHierarchy;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //super.configure(http);

        http
                .authorizeRequests(request -> {
                    request
                            // Root Page는 누구나 접근가능
                            .antMatchers("/").permitAll()
                            // 그 외 모든 요청에 대해서는 인가된 요청만 허용
                            .anyRequest().authenticated();
                })
                .formLogin(login -> {
                    login.loginPage("/login").permitAll()
                    .defaultSuccessUrl("/", false)
                    .failureUrl("/login-error")
                    .authenticationDetailsSource(customAuthDetail);
                })
                .logout(logout -> logout.logoutSuccessUrl("/"))
                .exceptionHandling(exception -> exception.accessDeniedPage("/access-denied"));
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        //super.configure(web);

        // Web Static Resources 접근 허용
        web.ignoring()
                .requestMatchers(
                        PathRequest.toStaticResources().atCommonLocations()
                );
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
