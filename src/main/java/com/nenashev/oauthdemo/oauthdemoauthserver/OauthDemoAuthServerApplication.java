package com.nenashev.oauthdemo.oauthdemoauthserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class OauthDemoAuthServerApplication {

    public static void main(final String[] args) {
        SpringApplication.run(OauthDemoAuthServerApplication.class, args);
    }

}
