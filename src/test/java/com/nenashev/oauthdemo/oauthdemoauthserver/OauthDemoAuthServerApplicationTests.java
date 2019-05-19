package com.nenashev.oauthdemo.oauthdemoauthserver;

import com.nenashev.oauthdemo.oauthdemoauthserver.db.AccessTokenRepository;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
@SpringBootTest
@ActiveProfiles("test")
public class OauthDemoAuthServerApplicationTests {

    @MockBean
    private AccessTokenRepository accessTokenRepository;

    @Test
    public void contextLoads() {
    }
}
