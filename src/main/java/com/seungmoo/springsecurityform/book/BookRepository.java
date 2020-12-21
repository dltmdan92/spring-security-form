package com.seungmoo.springsecurityform.book;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface BookRepository extends JpaRepository<Book, Integer> {

    // Spring Security에서 @Query 내 spring expression 안에서 principal을 사용할 수 있게 해준다.
    // 여기서 principal은 UserDetailsService에서 리턴하는 User 객체
    @Query("select b from Book b where b.author.id = ?#{principal.account.id}")
    List<Book> findCurrentUserBooks();
}
