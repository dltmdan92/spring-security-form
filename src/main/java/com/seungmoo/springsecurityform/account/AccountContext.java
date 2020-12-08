package com.seungmoo.springsecurityform.account;

/**
 * 쓰레드 로컬을 사용하는 예제를 만들어보자
 * SecurityContextHolder의 기본 전략 : ThreadLocal (java.lang 패키지에서 제공)
 */
public class AccountContext {

    private static final ThreadLocal<Account> ACCOUNT_THREAD_LOCAL = new ThreadLocal<>();

    public static void setAccount(Account account) {
        ACCOUNT_THREAD_LOCAL.set(account);
    }

    public static Account getAccount() {
        return ACCOUNT_THREAD_LOCAL.get();
    }
}
