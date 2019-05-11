package com.nenashev.oauthdemo.oauthdemoclient.config;

import com.nenashev.oauthdemo.oauthdemoclient.model.OauthClient;

import java.util.ArrayList;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties("oauth.auth-server")
public class OauthConfig {

    private List<OauthClient> clients = new ArrayList<>();

    private String authorizationEndpoint;
    private String tokenEndpoint;

    public List<OauthClient> getClients() {
        return clients;
    }

    public void setClients(final List<OauthClient> clients) {
        this.clients = clients;
    }

    public String getAuthorizationEndpoint() {
        return authorizationEndpoint;
    }

    public void setAuthorizationEndpoint(final String authorizationEndpoint) {
        this.authorizationEndpoint = authorizationEndpoint;
    }

    public String getTokenEndpoint() {
        return tokenEndpoint;
    }

    public void setTokenEndpoint(final String tokenEndpoint) {
        this.tokenEndpoint = tokenEndpoint;
    }

    @Override
    public String toString() {
        return "OauthConfig{" +
            "clients=" + clients +
            ", authorizationEndpoint='" + authorizationEndpoint + '\'' +
            ", tokenEndpoint='" + tokenEndpoint + '\'' +
            '}';
    }
}
