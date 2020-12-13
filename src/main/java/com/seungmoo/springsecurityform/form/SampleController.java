package com.seungmoo.springsecurityform.form;

import com.seungmoo.springsecurityform.account.AccountContext;
import com.seungmoo.springsecurityform.account.AccountRepository;
import com.seungmoo.springsecurityform.common.SecurityLogger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.security.Principal;
import java.util.concurrent.Callable;

@Controller
public class SampleController {

    @Autowired
    SampleService sampleService;

    @Autowired
    AccountRepository accountRepository;

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
     * @return
     */
    @GetMapping("/dashboard")
    public String dashboard(Model model, Principal principal) {
        model.addAttribute("message", "Hello " + principal.getName());
        sampleService.getAuthInfo();

        // Spring Security에서 Authenticate하면서 ThreadLocal에 Authentication 객체를 넣는다.
        // ThreadLocal을 통해 굳이 Principal을 파라미터로 주지 않아도 User 정보를 찾을 수 있다.
        sampleService.dashboard();
        return "dashboard"; // 뷰 이름 리턴, 해당 뷰를 찾아서 response를 담아서 보내준다.
    }

    @GetMapping("/admin")
    public String admin(Model model, Principal principal) {
        model.addAttribute("message", "Hello Admin, " + principal.getName());
        return "admin"; // 뷰 이름 리턴, 해당 뷰를 찾아서 response를 담아서 보내준다.
    }

    /**
     * USER 권한을 가진 계정만 접근하도록 한다.
     * AccessDecisionManager(인가) 실습
     * @param model
     * @param principal
     * @return
     */
    @GetMapping("/user")
    public String user(Model model, Principal principal) {
        model.addAttribute("message", "Hello User, " + principal.getName());
        return "user";
    }

    /**
     * Async한 핸들러는 Callable을 리턴할 수 있다.
     *
     * 해당 request를 처리하던 쓰레드를 release 하고,
     * Callable 안의 프로세스가 완료되면 그 응답을 또 release 한다.
     *
     * 핸들러의 쓰레드와 Callable 쓰레드가 다르지만,
     * Principal 정보는 동일함을 확인해보자. --> WebAsyncManagerIntegrationFilter 의 역할
     *
     * <WebAsyncManagerIntegrationFilter>
     * 스프링 MVC의 Async 기능(핸들러에서 Callable리턴할 수 있는 기능)을 사용할 때도
     * SecurityContext를 공유하도록 도와주는 필터 --> 동일한 Principal을 참조할 수 있음.
     * ●	PreProcess: SecurityContext를 설정한다. --> SecurityContext를 새로 만들어지는 Thread에 Integration해줌.
     * ●	Callable: 비록 다른 쓰레드지만 그 안에서는 동일한 SecurityContext를 참조할 수 있다.
     * ●	PostProcess: SecurityContext를 정리(clean up)한다. (참고로 SecurityContext는 매 req가 끝날 때마다 clean up 되야함)
     */
    @GetMapping("/async-master")
    @ResponseBody
    public Callable<String> asyncHandler() {
        // 여기는 톰캣이 할당해준 nio 쓰레드에서 실행
        SecurityLogger.log("MVC");

        // 이거는 별도의 쓰레드에서 실행
        return new Callable<String>() {
            @Override
            public String call() throws Exception {
                SecurityLogger.log("Callable");
                return "Async Handler";
            }
        };
    }

}
