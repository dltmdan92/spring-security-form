package com.seungmoo.springsecurityform.account;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@SpringBootTest
@AutoConfigureMockMvc
public class SignUpControllerTest {
    @Autowired
    MockMvc mockMvc;

    @Test
    public void signUpForm() throws Exception {
        mockMvc.perform(get("/signup"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("_csrf")));
    }

    /**
     * CSRF Token이 없어서 실패 발생!! (403 Forbidden)
     * --> .with(csrf())) 를 통해서 테스트용 CSRF를 넣어준다.
     * 화면에서는 CSRF Token에 tag에 자동 생성된다.
     * @throws Exception
     */
    @Test
    public void processSignUp() throws Exception {
        mockMvc.perform(post("/signup")
                .param("username", "seungmoo")
                .param("password", "123")
                .with(csrf()))
                .andDo(print())
                .andExpect(status().is3xxRedirection());
    }
}