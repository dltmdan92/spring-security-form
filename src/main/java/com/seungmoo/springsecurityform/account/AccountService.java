package com.seungmoo.springsecurityform.account;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * 비즈니스 로직
 * UserDetailsService --> 인증을 위해 DAO를 통해 DB의 User 정보를 들고오는 interface.
 *                      --> 실제로 여기서 인증하지 않음.
 *                      --> DB는 RDB, NoSQL, 인메모리 등등 상관없음 (DB 연동은 직접 구현한다.)
 *
 * 직접 UserDetailsService implement해서 메소드 구현 하거나
 * SecurityConfig에서 configure 메소드 구현해서 accountService를 명시 해주는 방법
 * 이렇게 두가지 있다.
 */
@Service
public class AccountService implements UserDetailsService {

    /**
     * JPA 뿐만 아니라, NoSQL 또는 다른 RDB mapper 구현체를 통해 interface를 구현한다.
     */
    @Autowired
    AccountRepository accountRepository;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        Account account = accountRepository.findByUsername(s);
        if (account == null) {
            throw new UsernameNotFoundException(s);
        }

        // Spring Security에서 제공해주는 User 클래스를 활용
        return User.builder()
                .username(account.getUsername())
                .password(account.getPassword())
                .roles(account.getRole())
                .build();
    }

    public Account createNew(Account account) {
        // 패스워드 인코딩 필수 (스프링 시큐리티 최근 버전 부터...)
        // 회원 가입의 경우 password encoding 이게 젤 중요하다.
        account.encodePassword(passwordEncoder);
        return this.accountRepository.save(account);
    }
}
