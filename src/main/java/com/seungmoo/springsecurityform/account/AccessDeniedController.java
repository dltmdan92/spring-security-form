package com.seungmoo.springsecurityform.account;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.security.Principal;

@Controller
public class AccessDeniedController {

    /**
     * SecurityConfig에서 "/access-denied" 로 포워딩해서 받는다.
     * @param principal
     * @param model
     * @return
     */
    @GetMapping("/access-denied")
    public String accessDenied(Principal principal, Model model) {
        model.addAttribute("name", principal.getName());
        return "access-denied";
    }
}
