package com.nenashev.oauthdemo.oauthdemoclient.model;

import java.util.Objects;

import org.springframework.data.annotation.Id;

public class AccessTokenInfo {

    @Id
    private String id;

    private String accessToken;
    private String clientId;
    private String scope;

    public AccessTokenInfo() {
    }

    public AccessTokenInfo(final String accessToken, final String clientId, final String scope) {
        this.accessToken = accessToken;
        this.clientId = clientId;
        this.scope = scope;
    }

    public String getId() {
        return id;
    }

    public void setId(final String id) {
        this.id = id;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(final String accessToken) {
        this.accessToken = accessToken;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(final String clientId) {
        this.clientId = clientId;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(final String scope) {
        this.scope = scope;
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        final AccessTokenInfo that = (AccessTokenInfo) o;
        return Objects.equals(id, that.id) &&
            Objects.equals(accessToken, that.accessToken) &&
            Objects.equals(clientId, that.clientId) &&
            Objects.equals(scope, that.scope);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

    @Override
    public String toString() {
        return "AccessTokenInfo{" +
            "id='" + id + '\'' +
            ", accessToken='" + accessToken + '\'' +
            ", clientId='" + clientId + '\'' +
            ", scope='" + scope + '\'' +
            '}';
    }
}
