package com.nenashev.oauthdemo.oauthdemoclient.model;

import java.util.ArrayList;
import java.util.List;

public class OauthClient {
    private String clientId;
    private String clientSecret;
    private List<String> redirectUris = new ArrayList<>();
    private String scope;

    public String getClientId() {
        return clientId;
    }

    public void setClientId(final String clientId) {
        this.clientId = clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(final String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public List<String> getRedirectUris() {
        return redirectUris;
    }

    public void setRedirectUris(final List<String> redirectUris) {
        this.redirectUris = redirectUris;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(final String scope) {
        this.scope = scope;
    }

    @Override
    public String toString() {
        return "OauthClient{" +
            "clientId='" + clientId + '\'' +
            ", clientSecret='" + "<HIDDEN>" + '\'' +
            ", redirectUris=" + redirectUris +
            ", scope='" + scope + '\'' +
            '}';
    }
}
