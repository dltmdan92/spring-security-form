package com.seungmoo.springsecurityform.form;

import com.seungmoo.springsecurityform.account.Account;
import com.seungmoo.springsecurityform.account.AccountService;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringRunner;

import static org.junit.Assert.*;

@RunWith(SpringRunner.class)
@SpringBootTest
public class SampleServiceTest {
    @Autowired
    SampleService sampleService;

    @Autowired
    AccountService accountService;

    @Autowired
    AuthenticationManager authenticationManager;

    @Test
    public void dashboard() {
        Account account = new Account();
        account.setRole("ADMIN"); // ADMIN > USER에 대한 Hierarchy를 설정했다. (MethodSecurity에서)
        account.setUsername("seungmoo");
        account.setPassword("123");
        accountService.createNew(account);

        // userDetails 가 Principal이다. (UserDetailsService에서 return 하는 객체가 곧 Principal이다.)
        UserDetails userDetails = accountService.loadUserByUsername("seungmoo");

        // UsernamePasswordAuthenticationToken을 만들려면 Principal과 Credential(password) 이 필요하다.
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(userDetails, "123");
        // 인증된 Authentication
        Authentication authentication = authenticationManager.authenticate(token);
        // 인증된 Authentication을 SecurityContextHolder에 넣어준다.
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // dashboard() 에 @Secured이 없으면 Service 객체에서 메서드 까지 접근이 가능하다.
        // BUT!! 비인증 or 권한 부족 인데 @Secured 애노테이션이 있으면 인증 Exception이 발생한다.
        // (AuthenticationCredentialNotFoundException)
        sampleService.dashboard();
    }

    /**
     * 인증/인가가 아닌 단지 메서드 기능에 대한 테스트라면
     * @WithMockUser로 수행할 수 있다.
     */
    @Test
    @WithMockUser
    public void dashboardWithMockUser() {
        sampleService.dashboard();
    }
}