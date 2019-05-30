package com.nenashev.oauthdemo.oauthdemoauthserver.scheduler;

import com.nenashev.oauthdemo.oauthdemoauthserver.db.AccessTokenRepository;
import com.nenashev.oauthdemo.oauthdemoauthserver.model.AccessTokenInfo;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
public class AccessTokenExpireScheduler {

    private final Logger logger = LoggerFactory.getLogger(AccessTokenExpireScheduler.class);

    private final AccessTokenRepository accessTokenRepository;

    private final Duration maxTokenAge;

    public AccessTokenExpireScheduler(final AccessTokenRepository accessTokenRepository,
                                      final @Value("${scheduling.access-token.max-age}") Duration maxTokenAge) {
        this.accessTokenRepository = accessTokenRepository;
        this.maxTokenAge = maxTokenAge;
    }

    @Scheduled(fixedDelayString = "${scheduling.delay}")
    public void checkAccessTokens() {
        logger.info("Checking for expired access tokens...");
        final Instant maxIssueDate = Instant.now().minus(maxTokenAge);
        final List<AccessTokenInfo> tokensToDelete = accessTokenRepository.findByIssueDateBefore(maxIssueDate);
        if (!tokensToDelete.isEmpty()) {
            logger.info("Found tokens: {}", tokensToDelete);
            accessTokenRepository.deleteAll(tokensToDelete);
            logger.info("Deleted {} expired tokens", tokensToDelete.size());
        } else {
            logger.info("No expired tokens found");
        }
    }
}
