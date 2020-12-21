package com.seungmoo.springsecurityform.form;

import com.seungmoo.springsecurityform.account.Account;
import com.seungmoo.springsecurityform.account.AccountContext;
import com.seungmoo.springsecurityform.common.SecurityLogger;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.Collection;

@Service
@Slf4j
public class SampleService {

    // Method Security의 Annotation이다.
    // 해당 메서드에 인증/인가된 User만 접근 가능
    // @Secured("ROLE_USER"), @RolesAllowed("ROLE_USER") : 메서드 호출 전에 권한 검사를 한다. SpEL 사용 불가
    // @PreAuthorize("hasRole(USER)") : 이것도 메서드 호출 전에 권한 검사 한다. SpEL 사용 가능
    // @PostAuthorize("hasRole(USER)") : 메서드 호출 후에 권한 검사를 한다. (메서드를 수행 후 후속 작업에 대해 막을 지 말지)
    // 메서드 시큐리티에서는 Web 용 시큐리티 설정(SecurityConfig) 클래스와는 별도로 설정해줘야 한다. ex) SecurityConfig에서 설정한 계층관계 모른다.
    @Secured("ROLE_USER")
    public void dashboard() {
        // SecurityContextPersistenceFilter가 Http Request 를 받아서 처리한다. (시큐리티 필터를 거치는 모든 요청)

        // SecurityContextPersistenceFilter는
        // Request가 들어오면, 먼저 캐싱된 SecurityContext를 찾다가 없으면
        // UsernamePasswordAuthenticationFilter(form 인증 처리하는 필터)에서 authenticate를 한다. --> AuthenticationManager를 사용해서 authenticate를 한다.
        // 그리고 authentication 기반의 SecurityContext를 SecurityContextHolder에 넣어준다.
        // AbstractAuthenticationProcessingFilter에서 SecurityContextHolder.getContext().setAuthentication(authResult); 실행된다.
        // 그리고 나서 목적 URL로 Redirect한다. 그리고 SecurityContextPersistenceFilter가 또 다시 Request를 받게 된다.
        // 그리고 HttpSessionSecurityContextRepository에서 SecurityContext를 가져온다. (SecurityContextPersistenceFilter에서)
        // 그리고 다시 SecurityContextHolder에 이 SecurityContext를 넣어준다.
        // 마지막으로 Request가 끝나면 SecurityContextPersistenceFilter는 SecurityContextHolder에서 Context를 제거한다.
        // 새로 고침을 하면 SecurityContextPersistenceFilter가 또 다시 Session에서 context를 불러온다. (Session이 바뀌면 인증정보가 날아감)
        // 만약 stateless하게(session 미사용) 한다면 매 요청마다 인증을 해야 한다.

        // Request가 끝나면 SecurityContextHolder에서 context를 clear한다.

        // 다중 요청에도 Context에 User authentication 정보를 들고 있음.
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        log.info("===================================");
        System.out.println(authentication);
        log.info(userDetails.getUsername());
    }

    public void getAuthInfo() {
        /**
         * 스프링 시큐리티 인증이 성공하면 SecurityContextHolder에 Authentication 정보가 등록된다.
         * logout 하면 authentication 정보가 제거 및 isAuthenticated도 false
         *
         * SecurityContextHolder : Authentication을 담고 있는 것.
         * AuthenticationManager : Authentication을 하는 것. (기본 구현체 : ProviderManager)
         */

        /**
         * SecurityContextHolder 는 ThreadLocal(기본 전략)을 사용하여 Authentication 정보를 제공한다.
         * ThreadLocal : 하나의 쓰레드가 공유하는 저장소 --> 이를 통해 파라미터를 통하지 않고 데이터에 접근 가능하다.
         * 일반적으로 request가 들어와서 response를 주는 로직은 하나의 쓰레드에서 처리한다.
         *
         * 만약 Thread가 달라지면(ex 비동기, ThreadPool 사용 시) 이것을 쓸 수 없다.
         * UsernamePasswordAuthenticationToken 구현체 객체가 리턴된다.
         */
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        // principal : 인증한 사용자 정보
        // getPrincipal()은 Spring Security의 User 객체를 리턴한다. (UserDetailsService 에서 리턴한 User 객체를 말하는 것)
        Object principal = authentication.getPrincipal();

        // 사용자가 가진 권한
        // authority는 SimpleGrantedAuthority가 리턴된 것임.
        // User 객체를 만들때 "ROLE_USER, ROLE_ADMIN" 이런식으로 권한을 생성한다.
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();

        /**
         * 인증이 된 Authentication 객체는 SecurityContextHolder에 담긴다.
         * 이때 credentials(Password)는 없음.
         */
        Object credentials = authentication.getCredentials();

        boolean authenticated = authentication.isAuthenticated();
    }

    /**
     * @Async : 특정 Bean 안의 메소드 호출할 떄, 별도의 쓰레드를 만들어서 비동기하게 처리한다.
     *
     * BUT @Async 애노테이션만 붙여서는 Async 처리가 안된다.
     * Application Class에 @EnableAsync를 붙여 줘야 적용된다.
     */
    @Async
    public void asyncService() {
        // 여기서 쓰레드가 완전 다르기 때문에 Principal이 없다. --> 로그찍을 때 NullPointerException이 발생된다.
        // SecurityContext가 공유되지 않는다.
        // SecurityContextHolder의 strategy에 SecurityContextHolder.MODE_INHERITABLETHREADLOCAL 잡아주면 공유된다.
        SecurityLogger.log("Async Service");
        System.out.println("Async service is called.");
    }
}
