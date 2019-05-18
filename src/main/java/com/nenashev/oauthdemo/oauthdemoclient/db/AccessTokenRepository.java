package com.nenashev.oauthdemo.oauthdemoclient.db;

import com.nenashev.oauthdemo.oauthdemoclient.model.AccessTokenInfo;

import org.springframework.data.mongodb.repository.MongoRepository;

public interface AccessTokenRepository extends MongoRepository<AccessTokenInfo, String> {
}
