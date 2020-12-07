package com.seungmoo.springsecurityform.account;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import static org.junit.Assert.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.anonymous;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@SpringBootTest
@AutoConfigureMockMvc // 이걸 써주면 @Autowired로 MockMvc를 받아서 쓸 수 있음
public class AccountControllerTest {
    @Autowired
    MockMvc mockMvc;

    /**
     * anonymous 익명 테스트
     * @throws Exception
     */
    @Test
    public void index_anonymous() throws Exception {
        mockMvc.perform(get("/").with(anonymous()))
                .andDo(print())
                .andExpect(status().isOk());
    }

    /**
     * 어노테이션으로 익명 테스트
     * @throws Exception
     */
    @Test
    @WithAnonymousUser
    public void with_anonymous() throws Exception {
        mockMvc.perform(get("/"))
                .andDo(print())
                .andExpect(status().isOk());
    }

    /**
     * 가짜 user를 만들어서 test 해보자
     * spring security의 SecurityMockMvcRequestPostProcessors.user 사용
     * 해당 가짜 user가 있다고 가정하고, 로그인 시킨 상태임. (mocking)
     * --> 그랬을 때의 테스트를 진행해보자.
     * @throws Exception
     */
    @Test
    public void index_user() throws Exception {
        mockMvc.perform(get("/").with(user("seungmoo").roles("USER"))) // 굳이 password는 필요하지 않음 --> 로그인 됐다고 가정.
                .andDo(print())
                .andExpect(status().isOk());
    }

    /**
     * 어노테이션으로 mock user 만들기
     * 굳이 코드 내에 명시하지 않아도 되는 장점이 있다.
     * @throws Exception
     */
    @Test
    @WithUser
    public void index_mock_user() throws Exception {
        mockMvc.perform(get("/")) // 굳이 password는 필요하지 않음 --> 로그인 됐다고 가정.
                .andDo(print())
                .andExpect(status().isOk());
    }

    /**
     * USER 권한으로 ADMIN에 접속하면
     * FORBIDDEN 403 발생한다.
     * @throws Exception
     */
    @Test
    @WithUser
    public void admin_user() throws Exception {
        mockMvc.perform(get("/admin"))
                .andDo(print())
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "admin", roles = "ADMIN")
    public void admin_admin() throws Exception {
        mockMvc.perform(get("/admin"))
                .andDo(print())
                .andExpect(status().isOk());
    }
}