package com.seungmoo.springsecurityform.account;

import org.springframework.data.jpa.repository.JpaRepository;

/**
 * 이렇게 인터페이스만 만들어도
 * 해당 인터페이스의 구현체가 자동으로 만들어지고
 * Bean으로 등록까지 된다.
 */
public interface AccountRepository extends JpaRepository<Account, Integer> {
    Account findByUsername(String s);
}
