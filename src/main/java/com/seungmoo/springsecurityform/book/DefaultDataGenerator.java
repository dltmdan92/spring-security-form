package com.seungmoo.springsecurityform.book;

import com.seungmoo.springsecurityform.account.Account;
import com.seungmoo.springsecurityform.account.AccountService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

@Component
public class DefaultDataGenerator implements ApplicationRunner {

    @Autowired
    AccountService accountService;

    @Autowired
    BookRepository bookRepository;

    @Override
    public void run(ApplicationArguments args) throws Exception {
        // seungmoo는 spring 책을
        // sam은 - hibernate 책을 썼다고 가정
        Account seungmoo = createUser("seungmoo");
        Account sam = createUser("sam");

        createBook("spring", seungmoo);
        createBook("hibernate", sam);
    }

    private void createBook(String title, Account seungmoo) {
        Book book = new Book();
        book.setTitle(title);
        book.setAuthor(seungmoo);
        bookRepository.save(book);
    }

    private Account createUser(String username) {
        Account account = new Account();
        account.setUsername(username);
        account.setPassword("123");
        account.setRole("USER");
        return this.accountService.createNew(account);
    }
}
