package com.seungmoo.springsecurityform.config;

import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.access.expression.WebExpressionVoter;

import java.util.Arrays;
import java.util.List;

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
@Order(Ordered.LOWEST_PRECEDENCE - 100) // Config의 Order 설정 (숫자가 낮을 수록 우선순위)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    /**
     * ROLE hierarchy 적용한 AccessDecisionManager를 만들었다.
     * @return
     */
    public AccessDecisionManager accessDecisionManager() {
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        roleHierarchy.setHierarchy("ROLE_ADMIN > ROLE_USER");

        DefaultWebSecurityExpressionHandler defaultWebSecurityExpressionHandler = new DefaultWebSecurityExpressionHandler();
        defaultWebSecurityExpressionHandler.setRoleHierarchy(roleHierarchy);

        WebExpressionVoter webExpressionVoter = new WebExpressionVoter();
        webExpressionVoter.setExpressionHandler(defaultWebSecurityExpressionHandler);
        List<AccessDecisionVoter<? extends Object>> voters = List.of(webExpressionVoter);
        return new AffirmativeBased(voters);
    }

    /**
     * 위의 기능과 같음 .expressionHandler에 넣어준다.
     * @return
     */
    public SecurityExpressionHandler securityExpressionHandler() {
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        roleHierarchy.setHierarchy("ROLE_ADMIN > ROLE_USER");

        DefaultWebSecurityExpressionHandler defaultWebSecurityExpressionHandler = new DefaultWebSecurityExpressionHandler();
        defaultWebSecurityExpressionHandler.setRoleHierarchy(roleHierarchy);

        return defaultWebSecurityExpressionHandler;
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        // FilterChainProxy에서 favicon 요청은 filter 적용 무시한다.
        // 1. 필요없는 filters 적용 방지 (실제로 필터를 하나도 안탄다. 빠름)
        // 2. .anyRequest().authenticated() --> 이거 때문에 익명 비인증 사용자의 경우 인증못받아서 /login로 이동하는 현상 방지
        //web.ignoring().mvcMatchers("/favicon.ico"); // 매번 이렇게 static resource를 명시하는 것은 불편...

        // 이렇게 정적 리소스 요청 시 선언해주면 더 편하다. 이 방법이 가장 낫다.
        // 스프링 시큐리티 적용안할 리소스는 이렇게 필터에서 먼저 아예 제외하는 게 좋다.
        web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // FilterChain 설정, 여러 개의 FilterChain이 있을 경우 @Order 순위를 따른다.
        // 여기서 선언하는 것들에 따라 Filter들의 설정이 달라지는 것이다.
        // 동적 리소스는 여기서 필터 적용해주는 것이 좋다. (동적 리소스는 필터를 태우는게 맞음.)
        http.antMatcher("/**") // antMatcher 설정을 안하면 모든 요청을 해당 필터에 맵핑한다.
                .authorizeRequests()
                .mvcMatchers("/", "/info", "/account/**").permitAll() // 인증 없이도 접근 가능
                .mvcMatchers("/admin").hasRole("ADMIN")

                // ADMIN인데 USER 페이지에는 접근을 못하는 건가???
                // Spring Security는 ROLE_ADMIN, ROLE_USER 이런거 모른다. --> 어떻게 할까??
                // 방법 1. ADMIN user의 경우, User.buider() 할 때 ADMIN 권한과 함께, USER 권한도 같이 준다.
                // 방법 2. AccessDecisionManager가 ROLE들의 hierarchy를 이해하도록 설정한다. (직접 만듦)
                .mvcMatchers("/user").hasRole("USER")
                //.accessDecisionManager(accessDecisionManager()) // AccessDecisionManager를 직접 만들어서 넣어준다.

                // 이렇게 하면 favicon 요청에 대해서 filter 15개를 전부 다 탄다. (안좋음)
                //.requestMatchers(PathRequest.toStaticResources().atCommonLocations()).permitAll() --> 이거는 비추천, 느리다.
                .anyRequest().authenticated()

                // AccessDecisionManager 커스텀 셋팅하지 말고 이렇게 셋팅해도 된다.
                // AccessDecisionManager는 그냥 디폴트이고, AccessDecisionVoter가 사용하는 ExpressionHandler만 바꾼것임.
                .expressionHandler(securityExpressionHandler())
        ;

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
