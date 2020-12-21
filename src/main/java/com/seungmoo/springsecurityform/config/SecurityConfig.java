package com.seungmoo.springsecurityform.config;

import com.seungmoo.springsecurityform.account.AccountService;
import com.seungmoo.springsecurityform.common.LoggingFilter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.access.expression.WebExpressionVoter;
import org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
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
@Slf4j
@Configuration
@EnableWebSecurity // 이거 빼도 된다. 스프링부트에서는 자동설정이 알아서 추가해주기 때문임.
@Order(Ordered.LOWEST_PRECEDENCE - 100) // Config의 Order 설정 (숫자가 낮을 수록 우선순위)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    AccountService accountService;

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

        // WebAsyncManagerIntegrationFilter가 FilterChain에서 가장 앞에 있는 Filter임
        // FilterChain 맨 앞에 넣음으로써 성능 측정이나 해보자.
        http.addFilterBefore(new LoggingFilter(), WebAsyncManagerIntegrationFilter.class);

        // FilterChain 설정, 여러 개의 FilterChain이 있을 경우 @Order 순위를 따른다.
        // 여기서 선언하는 것들에 따라 Filter들의 설정이 달라지는 것이다.
        // 동적 리소스는 여기서 필터 적용해주는 것이 좋다. (동적 리소스는 필터를 태우는게 맞음.)
        // FilterSecurityInterceptor : HTTP 리소스 시큐리티 처리를 담당하는 필터. AccessDecisionManager를 사용해서 인가를 처리한다.
        http.antMatcher("/**") // antMatcher 설정을 안하면 모든 요청을 해당 필터에 맵핑한다. /** : 앤트 패턴
                .authorizeRequests()
                .mvcMatchers("/", "/info", "/account/**", "/signup").permitAll() // 인증 없이도 접근 가능
                .mvcMatchers("/admin").hasRole("ADMIN") // hasAuthority("ROLE_ADMIN")와 동일하다. (hasRole에서는 ROLE_ 생략할 수 있다.)

                // ADMIN인데 USER 페이지에는 접근을 못하는 건가???
                // Spring Security는 ROLE_ADMIN, ROLE_USER 이런거 모른다. --> 어떻게 할까??
                // 방법 1. ADMIN user의 경우, User.buider() 할 때 ADMIN 권한과 함께, USER 권한도 같이 준다.
                // 방법 2. AccessDecisionManager가 ROLE들의 hierarchy를 이해하도록 설정한다. (직접 만듦)
                .mvcMatchers("/user").hasRole("USER") // hasAuthority("ROLE_USER")와 동일하다.
                //.accessDecisionManager(accessDecisionManager()) // AccessDecisionManager를 직접 만들어서 넣어준다.

                // 이렇게 하면 favicon 요청에 대해서 filter 15개를 전부 다 탄다. (안좋음)
                //.requestMatchers(PathRequest.toStaticResources().atCommonLocations()).permitAll() --> 이거는 비추천, 느리다.
                .anyRequest().authenticated()
                //.anyRequest().anonymous() // 익명 사용자만 접근할 수 있도록 한다. (인증이 되면 접근이 실패함)
                //.anyRequest().rememberMe() // rememberMe로 인증한 사용자만 접근을 허용
                //.anyRequest().fullyAuthenticated() // rememberMe로 인증한 사용자는 다시 로그인 해야 한다. (중요한 URL 접근 시 재 로그인 시키는 경우)
                // AccessDecisionManager 커스텀 셋팅하지 말고 이렇게 셋팅해도 된다.
                // AccessDecisionManager는 그냥 디폴트이고, AccessDecisionVoter가 사용하는 ExpressionHandler만 바꾼것임.
                .expressionHandler(securityExpressionHandler())
        ;

        // form login 사용  /login으로 접속하면 login 창이 뜬다. /logout 접속 시 로그아웃 기능
        http.formLogin()
                // login 페이지의 username, password element의 name값을 바꿔줄 수 있다.
                //.usernameParameter("my-username")
                //.passwordParameter("my-password")

                // 로그인 페이지 커스텀해서 설정할 수 있으나, 이 옵션을 추가하는 순간
                // DefaultLoginPageGeneratingFilter, LogoutFilter가 등록되지 않는다. (FilterChainProxy에서 확인해볼 수 있다.)
                // 위의 두 필터에 대해서 직접 구현해줘야 한다.
                // 그리고 이거 셋팅해주면 /logout page도 없어지기 때문에, 별도로 만들어줘야 한다.
                .loginPage("/login") // 설정한 URL로 로그인 req가 호출된다.
                .permitAll() // 이거 안해주면 화면 안뜸
                ;

        /**
         * Basic 인증이란??
         * RequestHeader에 username과 password를 실어 보내면 브라우저 또는 서버가 그 값을 읽어서 인증하는 방식
         * 예) Authorization: Basic QWxhZGRpbjpPcGVuU2VzYW1l (keesun:123 을 BASE 64로 인코딩)
         * Http Header의 위의 정보를 담아서 보냄 --> 요청이 snipping 당하게 되면 위험!! --> HTTPS 를 사용하는 것이 좋다.
         *
         * Basic 인증 방식은 BasicAuthenticationFilter가 받는다. (여기서도 AuthenticationManager로 인증한다.)
         * UsernamePasswordAuthenticationFilter와의 차이점 --> BasicAuthenticationFilter는 Request Header를 본다.
         *
         */
        http.httpBasic(); // http basic 인증을 사용 (BasicAuthenticationFilter)

        http.logout()
                // 실제 로그아웃 처리를 담당하는 logout 페이지인데 /logout 으로 셋팅하는게 좋다.
                // 기본적으로 로그아웃 처리하는 path 또한 /logout으로 Spring Security가 Default 셋팅하는데
                // 여기서 logout 페이지를 /mylogout 이런식으로 하면 별도의 커스텀이 또 필요하다.
                // 그리고 이거는 그냥 설정 생략하면 된다.
                //.logoutUrl("/logout")

                .logoutSuccessUrl("/")
                //.addLogoutHandler() // 핸들러를 추가할 수 있다.

                // logout 한 다음에 HttpSession을 invalid 처리할 것인가?
                // 기본값이 true 이므로 그냥 생략하면 된다. (대부분의 경우 true로 처리하니까 생략 ㄱㄱ)
                //.invalidateHttpSession(true)

                // 쿠키를 사용하는 경우, 로그아웃 한 다음에는 그 쿠키를 없애주는 것이 좋다.
                //.deleteCookies("쿠키이름")
                ;

        // anonymous authentication을 설정해줄 수 있다.
        // 현재 SecurityContextHolder에 셋팅된 Authentication이 없는 경우에 (null 인 경우),
        // 새로운 Anonymous Authentication을 만들어서 Context에 넣어준다.

        // 만약 SecurityContextHolder에 셋팅된 Authentication이 null이 아니면 아무일도 안함.
        http.anonymous().principal("anonymousUser"); // anonymousUser가 디폴트임.

        /**
         * RememberMeAuthenticationToken 을 생성하여 인증할 수 있도록 한다.
         * 세션이 사라지거나 만료가 되더라도 쿠키 또는 DB를 사용하여 저장된 토큰 기반으로 인증을 지원하는 필터
         * 로그인 시 인증할 때 "remember-me" input tag name으로 submit 호출하면 인증 및 토큰 생성 된다.
         * UsernamePasswordAuthenticationToken과는 별도로 생성되며, RememberMeAuthenticationFilter에서 인증한다.
         *
         * 쿠키에 토큰이 셋팅된다. --> 그 쿠키에 있는 토큰을 사용해서 인증한다.
         * (참고로 UsernamePassword 로 로그인했을 때의 UsernamePasswordAuthentication 또한 SESSION 생성되면서 JSESSION_ID가 쿠키에 셋팅된다.)
         */
        http.rememberMe()
                .userDetailsService(accountService)
                .key("remember-me-sample");

        /**
         * 세션 변조으로 인해 보안 이슈가 발생할 수 있다.
         * SessionManagementFilter를 통해 sessionFixation "세션 변조 방지 전략"을 설정할 수 있다.
         * ●	none
         * ●	newSession --> 세션을 그냥 새로 만드는 것
         * ●	migrateSession (서블릿 3.0- 컨테이너 사용시 기본값)
         * ●	changeSessionId (서브릿 3.1+ 컨테이너 사용시 기본값)
         */
        http.sessionManagement()
                // 세션 생성 전략 IF_REQUIRED 기본값
                // form 기반의 security에서는 SessionCreationPolicy.STATELESS 이거 쓰면 안된다. (세션을 안 만든다는 것임...)
                // 세션 안만들면 로그인만 계속하게 될 거다.
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                .sessionFixation()
                    //.newSession()// 세션ID 변조가 아닌 신규 session을 만든다. (안좋음)
                    .changeSessionId()
                .invalidSessionUrl("/login") // 유효하지 않은 세션이 접근했을 때 어디로 보낼 것인가.
                .maximumSessions(1) // 동시성 관리, 하나의 계정이 여러 곳에서 로그인할 수 있을지 설정, 1로 설정하면 동시에 하나만 로그인
                    // 다른 브라우저에서 로그인하면서 maximumSession 로그인 갯수가 다 차게 되면, 이전에 로그인했던 세션은 만료가 된다.
                    // 이 때 만료된 세션을 어느 URL로 보낼지 설정한다.
                    .expiredUrl("/login")
                    // maxSession을 넘기는 추가로그인을 허용할지, 막을지 설정. 기본값은 false(추가 로그인 허용)
                    // 이걸 true로 하면 먼저 로그인한 사람이 계속 점유하게 된다. (ID 탈취한 사람이 계속 점유하는 케이스 --> 위험!)
                    .maxSessionsPreventsLogin(false)
        ;

        // TODO ExceptionTranslatorFilter -> FilterSecurityInterceptor (AccessDecisionManager, AffirmativeBased 구현체 사용해서 인가처리)
        // 발생할 수 있는 에러
        // 1. AuthenticationException --> AuthenticationEntryPoint에서 예외처리 (인증이 가능한 페이지(login)로 보냄, 인증안된 상태에서 /dashboard 페이지 들어갈 때)
        // 2. AccessDeniedException --> AccessDeniedHandler에서 예외처리 (기본적으로는 403 FORBIDDEN ERROR를 보여주고 error페이지로 간다. USER role 계정으로 ADMIN 접근할 때)
        // 근데 AccessDeniedException 발생 시 이동하는 페이지가 안 이쁘다 --> Custom해서 User 친화적인 페이지를 만들어 주자.
        // ExceptionTranslatorFilter는 FilterSecurityInterceptor를 감싸서 실행해야 한다.
        // FilterSecurityInterceptor를 try catch로 감싸서 실행한다.
        http.exceptionHandling()
                //.accessDeniedPage("/access-denied")
                // Handler를 만들어서 좀 더 기능을 추가해보자.
                .accessDeniedHandler(new AccessDeniedHandler() {
                    // 핸들러는 가급적 별도 클래스에 빼도록 한다.
                    @Override
                    public void handle(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AccessDeniedException e) throws IOException, ServletException {
                        UserDetails principal = (UserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
                        String username = principal.getUsername();
                        // 실패 로그 남겨서 비정상적인 접속에 대한 기록을 남겨보자.
                        log.info(username + " is denied to access " + httpServletRequest.getRequestURI());
                        // 그리고 "/access-denied" 로 포워딩하자.
                        httpServletResponse.sendRedirect("/access-denied");
                    }
                });

        /**
         * 스프링 시큐리티의 기본 user 정보는
         * UserDetailsServiceAutoConfiguration 에서 생성함. (inMemoryUserDetailsManager --> SecurityProperties 참고)
         */

        // SecurityContextHolder.MODE_INHERITABLETHREADLOCAL --> 현재 쓰레드 기준에서 생성되는 하위쓰레드에도 SecurityContext가 공유된다.
        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);

        // 기본적으로 CSRF 토큰은 자동으로 생성 및 필터 처리한다.
        // CSRF 토큰 미사용 처리 (form 기반 웹 서비스는 csrf 반드시 사용하도록 한다.
        // REST API는 매번 CSRF 토큰 보내기가 번거롭기 때문에 보통 생략하게 된다.
        //http.csrf().disable();
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

    /**
     * AuthenticationManager를 사용하기 위해서 Bean으로 등록해준다.
     * @return
     * @throws Exception
     */
    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}
