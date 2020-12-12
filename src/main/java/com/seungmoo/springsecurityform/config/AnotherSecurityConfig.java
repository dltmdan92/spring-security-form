package com.seungmoo.springsecurityform.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity // 스프링부트에서는 생략가능
@Order(Ordered.LOWEST_PRECEDENCE - 15) // Config의 Order 설정 (숫자가 낮을 수록 우선순위)
public class AnotherSecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // FilterChain 설정, 여러 개의 FilterChain이 있을 경우 @Order 순위를 따른다.
        http.antMatcher("/account/**") // antMatcher 설정을 안하면 모든 요청을 해당 필터에 맵핑한다.
                .authorizeRequests()
                .anyRequest().authenticated(); // permitAll설정 시 총 15개의 SecurityFilter들 중에, form인증 및 httpbasic 등 필터가 사라진다.
        http.formLogin();
        http.httpBasic();
    }
}
