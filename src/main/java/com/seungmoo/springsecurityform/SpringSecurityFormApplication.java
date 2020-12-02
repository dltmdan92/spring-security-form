package com.seungmoo.springsecurityform;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
public class SpringSecurityFormApplication {

    @Bean
    public PasswordEncoder passwordEncoder() {
        /**
         * 원래 스프링 시큐리티의 Encoding Strategy는 NoOp 이었다.
         * 스프링 시큐리티 5버전 부터 BCRYPT 방식으로 기본 전략이 바뀌었다.
         */
        //return NoOpPasswordEncoder.getInstance(); --> Deprecated 되었음

        // 스프링 시큐리티에서 현재 권장하는 encoder 생성 방식
        // 다양한 encoder 방식을 지원한다. 소스 까보면 HashMap에 첨가 되어있음
        return PasswordEncoderFactories.createDelegatingPasswordEncoder(); // 기본적으로는 bcrypt 사용함.
    }

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityFormApplication.class, args);
    }

}
