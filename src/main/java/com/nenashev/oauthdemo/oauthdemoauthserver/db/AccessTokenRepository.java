package com.nenashev.oauthdemo.oauthdemoauthserver.db;

import com.nenashev.oauthdemo.oauthdemoauthserver.model.AccessTokenInfo;

import java.time.Instant;
import java.util.List;

import org.springframework.context.annotation.Profile;
import org.springframework.data.mongodb.repository.MongoRepository;

@Profile("!test")
public interface AccessTokenRepository extends MongoRepository<AccessTokenInfo, String> {

    List<AccessTokenInfo> findByExpireDateBefore(Instant minDate);
}
