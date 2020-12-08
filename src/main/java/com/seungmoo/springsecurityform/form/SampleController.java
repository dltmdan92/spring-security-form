package com.seungmoo.springsecurityform.form;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.security.Principal;

@Controller
public class SampleController {

    @Autowired
    SampleService sampleService;

    @GetMapping("/")
    public String index(Model model, Principal principal) {

        // 로그인을 안했을 때
        if (principal == null) {
            model.addAttribute("message", "Hello Spring Security");
        }
        // 로그인을 했을 때
        else {
            model.addAttribute("message", "Hello, " + principal.getName());
        }

        return "index"; // 뷰 이름 리턴, 해당 뷰를 찾아서 response를 담아서 보내준다.
    }

    @GetMapping("/info")
    public String info(Model model) {
        model.addAttribute("message", "Info");
        return "info"; // 뷰 이름 리턴, 해당 뷰를 찾아서 response를 담아서 보내준다.
    }

    /**
     *
     * @param model
     * @param principal Principal interface의 구현체에는 스프링 시큐리티에서 Auth 정보가 forward 된다.
     *                  principal은 로그인이 된 상태에서 받아올 수 있음
     *
     *                  컨트롤러에서 굳이 파라미터로 Principal을 인입받지 않아도
     *                  SecurityContextHolder 에서 ThreadLocal을 사용해서 authentication 정보를 받을 수 있다.
     * @return
     */
    @GetMapping("/dashboard")
    public String dashboard(Model model, Principal principal) {
        model.addAttribute("message", "Hello " + principal.getName());
        sampleService.dashboard();
        return "dashboard"; // 뷰 이름 리턴, 해당 뷰를 찾아서 response를 담아서 보내준다.
    }

    @GetMapping("/admin")
    public String admin(Model model, Principal principal) {
        model.addAttribute("message", "Hello Admin, " + principal.getName());
        return "admin"; // 뷰 이름 리턴, 해당 뷰를 찾아서 response를 담아서 보내준다.
    }

}
