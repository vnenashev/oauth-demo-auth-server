package com.nenashev.oauthdemo.oauthdemoauthserver.db;

import com.nenashev.oauthdemo.oauthdemoauthserver.model.RefreshTokenInfo;

import org.springframework.context.annotation.Profile;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.lang.Nullable;

@Profile("!test")
public interface RefreshTokenRepository extends MongoRepository<RefreshTokenInfo, String> {

    @Nullable
    RefreshTokenInfo findByRefreshToken(String refreshToken);
}
