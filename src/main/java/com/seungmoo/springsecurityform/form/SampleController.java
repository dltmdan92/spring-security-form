package com.seungmoo.springsecurityform.form;

import com.seungmoo.springsecurityform.account.Account;
import com.seungmoo.springsecurityform.account.AccountContext;
import com.seungmoo.springsecurityform.account.AccountRepository;
import com.seungmoo.springsecurityform.account.UserAccount;
import com.seungmoo.springsecurityform.common.CurrentUser;
import com.seungmoo.springsecurityform.common.SecurityLogger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
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
    public String index(
            Model model,
            //Principal principal
            // 위의 Principal 객체 대신 UserAccount 객체를 받을 수 있다. (직접 만든 User 도메인)
            //@AuthenticationPrincipal UserAccount userAccount
            // 그리고 Account 객체를 직접 받는 방법도 있다.
            // anonymousUser 객체가 아닌 경우에는 Principal에서 account 객체를 꺼내 준다. (근데 너무 길다 별도 애노테이션으로 빼자)
            //@AuthenticationPrincipal(expression = "#this == 'anonymousUser' ? null : account") Account account
            @CurrentUser Account account // 이렇게 별도 애노테이션으로 빼서 Account 도메인을 현재 User로 직접 받아올 수 있다.
            ) {

        // 이 Principal은 위의 파라미터에 있는 Principal과는 다르다.
        // 이거는 UserDetailsService에서 리턴한 User 객체 이다.
        // 이 User 객체를 우리가 만든 Account 객체로 쓸 수 없을까???
        SecurityContextHolder.getContext().getAuthentication().getPrincipal();

        // 로그인을 안했을 때
        if (account == null) {
            model.addAttribute("message", "Hello Spring Security");
        }
        // 로그인을 했을 때
        else {
            model.addAttribute("message", "Hello, " + account.getUsername());
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
    @GetMapping("/async-handler")
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

    /**
     * Async한 Service를 호출해보자
     * @return
     */
    @GetMapping("/async-service")
    @ResponseBody
    public String asyncService() {
        SecurityLogger.log("MVC, before async service");
        sampleService.asyncService(); // 비동기 로직이므로 아래 로그에서 기다리지 않고 실행할 것임.(보장 X)
        SecurityLogger.log("MVC, after async service");
        return "Async Service";
    }

}
