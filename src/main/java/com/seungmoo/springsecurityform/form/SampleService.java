package com.seungmoo.springsecurityform.form;

import com.seungmoo.springsecurityform.account.Account;
import com.seungmoo.springsecurityform.account.AccountContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.Collection;

@Service
@Slf4j
public class SampleService {
    public void dashboard() {
        Account account = AccountContext.getAccount();
        log.info("===================================");
        log.info(account.getUsername());
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

        // 인증정보(password)가 담겨 있음 (UsernamePasswordAuthenticationToken 구현체의 경우)
        Object credentials = authentication.getCredentials();

        boolean authenticated = authentication.isAuthenticated();
    }
}
