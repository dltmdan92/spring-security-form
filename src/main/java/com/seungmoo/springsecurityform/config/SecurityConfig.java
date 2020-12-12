package com.seungmoo.springsecurityform.config;

import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * 스프링 WEB Security 셋팅 해보자
 */
/**
 * <Security Filter>
 * 여기서 여러개의 SecurityFilterChain을 만들 수 있다.
 * 그리고 FilterChainProxy.class에서 getFilters() 메소드를 통해 SecurityFilterChain들을 get하고
 * FilterChainProxy.VirtualFilterChain.doFilter를 통해 등록된 SecurityFilterChain들을 실행한다.
 * VirtualFilterChain.doFilter  메소드가 각 ServletRequest에 대해 등록된 Filter들을 실행한다.
 *
 * 참고로 DelegatingFilterProxy가 FilterChainProxy에게 필터 처리를 위임시킨다.
 * FilterChainProxy는 보통 "springSecurityFilterChain"의 이름으로 Bean 등록된다.
 * --> SecurityFilterAutoConfiguration에서 DEFAULT_FILTER_NAME = “springSecurityFilterChain”
 * --> 그리고 SecurityFilterAutoConfiguration가 DelegatingFilterProxy에게 해당 Bean("springSecurityFilterChain")을 알려준다.
 *
 */
@Configuration
@EnableWebSecurity // 이거 빼도 된다. 스프링부트에서는 자동설정이 알아서 추가해주기 때문임.
@Order(Ordered.LOWEST_PRECEDENCE - 10) // Config의 Order 설정 (숫자가 낮을 수록 우선순위)
public class SecurityConfig extends WebSecurityConfigurerAdapter {


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // FilterChain 설정, 여러 개의 FilterChain이 있을 경우 @Order 순위를 따른다.
        // 여기서 선언하는 것들에 따라 Filter들의 설정이 달라지는 것이다.
        http.antMatcher("/**") // antMatcher 설정을 안하면 모든 요청을 해당 필터에 맵핑한다.
                .authorizeRequests()
                .mvcMatchers("/", "/info", "/account/**").permitAll() // 인증 없이도 접근 가능
                .mvcMatchers("admin").hasRole("ADMIN")
                .anyRequest().authenticated();

       // form login 사용  /login으로 접속하면 login 창이 뜬다. /logout 접속 시 로그아웃 기능
        http.formLogin();

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
    /*
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
    */
}
