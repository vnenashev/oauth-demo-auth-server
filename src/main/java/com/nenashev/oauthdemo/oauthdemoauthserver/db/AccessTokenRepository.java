package com.nenashev.oauthdemo.oauthdemoauthserver.db;

import com.nenashev.oauthdemo.oauthdemoauthserver.model.AccessTokenInfo;

import org.springframework.data.mongodb.repository.MongoRepository;

public interface AccessTokenRepository extends MongoRepository<AccessTokenInfo, String> {
}
