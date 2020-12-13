package com.seungmoo.springsecurityform.account;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * 회원 가입 기능을 직접 만들어 봅시다. (signUp)
 * form으로 회원가입을 받을 수 있다.
 */
@Controller
@RequestMapping("/signup")
public class SignUpController {

    @Autowired
    AccountService accountService;

    /**
     * signup view 페이지에 CSRF 토큰 value 및 태그를 자동으로 넣어준다.
     * --> thymeleaf 2.1 이상 or JSP에서 form 태그를 사용하게 되면 spring security에서 자동으로 넣어준다.
     * @param model
     * @return
     */
    @GetMapping
    public String signupForm(Model model) {
        model.addAttribute("account", new Account());
        return "signup";
    }

    /**
     * CSRF 토큰 값 검증은 POST 요청일 때 수행한다.
     * GET 요청은 CSRF 토큰 값 확인 안함.
     * --> CsrfFilter.java 참고
     *
     * 토큰 값 안맞으면 AccessDeniedHandler로 던진다.
     * 
     * @param account
     * @return
     */
    @PostMapping
    public String processSignUp(@ModelAttribute Account account) {
        account.setRole("USER");
        accountService.createNew(account);

        // root 쪽으로 리다이렉트
        return "redirect:/";
    }
}
