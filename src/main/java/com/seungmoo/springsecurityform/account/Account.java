package com.seungmoo.springsecurityform.account;

import lombok.Getter;
import lombok.Setter;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;

@Entity
@Getter @Setter
public class Account {

    @Id @GeneratedValue
    private Integer id;

    @Column(unique = true)
    private String username;

    private String password;

    private String role;

    /**
     * 스프링 시큐리티 최근 버전 부터는
     * password에 인코딩 방식이 필수로 적용되어야 한다.
     * @param passwordEncoder
     */
    public void encodePassword(PasswordEncoder passwordEncoder) {
        //this.password = "{noop}" + this.password;

        // 위처럼 "{noop}" 이렇게 직접 인코딩 명시하지말고
        // PasswordEncoder Bean을 생성해서 갖다쓰는 방식
        // 인코딩 변경 시 Bean 선언 문에서 encoding 선언 메서드만 수정하면 된다.
        this.password = passwordEncoder.encode(this.password);
    }
}
