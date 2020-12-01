package com.seungmoo.springsecurityform.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * 스프링 WEB Security 셋팅 해보자
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .mvcMatchers("/", "/info").permitAll() // 인증 없이도 접근 가능
                .mvcMatchers("admin").hasRole("ADMIN")
                .anyRequest().authenticated();
        http.formLogin(); // form login 사용  /login으로 접속하면 login 창이 뜬다. /logout 접속 시 로그아웃 기능
        http.httpBasic(); // http의 basic authentication 사용

        /**
         * 스프링 시큐리티의 기본 user 정보는
         * UserDetailsServiceAutoConfiguration 에서 생성함. (inMemoryUserDetailsManager --> SecurityProperties 참고)
         */
    }

    /**
     * 우리가 원하는 user 정보를 설정할 수 있다.
     * @param auth
     * @throws Exception
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // {***} --> 스프링의 기본적인 패스워드 인코더 prefix, 해당 prefix에 해당하는 암호화(encoding)을 진행한다.
        // 그리고 암호화(encoding)된 password를 DB에 있는 값과 비교함
        // {***}123 --> ***방식으로 암호화된 "123" 값이 DB에 저장된다. (LHKJH#L@#J(*U% 이런식으로 DB에 저장된다는 말임)
        // {noop}은 encoding을 하지 않겠다는 말이다.  즉, {noop}123은 DB에 그냥 123으로 저장된다.
        auth.inMemoryAuthentication() // IN MEMORY로 USER를 미리 만들어보자. (실제론 이렇게 안함.. DB에 USER 정보 저장하고 인증함)
                .withUser("seungmoo").password("{noop}123").roles("USER").and()
                .withUser("admin").password("{noop}!@#").roles("ADMIN");
    }
}
