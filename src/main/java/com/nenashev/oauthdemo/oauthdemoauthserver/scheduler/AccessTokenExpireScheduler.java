package com.nenashev.oauthdemo.oauthdemoauthserver.scheduler;

import com.nenashev.oauthdemo.oauthdemoauthserver.db.AccessTokenRepository;
import com.nenashev.oauthdemo.oauthdemoauthserver.model.AccessTokenInfo;

import java.time.Instant;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
@Profile("!test")
public class AccessTokenExpireScheduler {

    private final Logger logger = LoggerFactory.getLogger(AccessTokenExpireScheduler.class);

    private final AccessTokenRepository accessTokenRepository;

    public AccessTokenExpireScheduler(final AccessTokenRepository accessTokenRepository) {
        this.accessTokenRepository = accessTokenRepository;
    }

    @Scheduled(fixedDelayString = "${scheduling.delay}")
    public void checkAccessTokens() {
        logger.info("Checking for expired access tokens...");
        final Instant now = Instant.now();
        final List<AccessTokenInfo> tokensToDelete = accessTokenRepository.findByExpireDateBefore(now);
        if (!tokensToDelete.isEmpty()) {
            logger.info("Found tokens: {}", tokensToDelete);
            accessTokenRepository.deleteAll(tokensToDelete);
            logger.info("Deleted {} expired tokens", tokensToDelete.size());
        } else {
            logger.info("No expired tokens found");
        }
    }
}
