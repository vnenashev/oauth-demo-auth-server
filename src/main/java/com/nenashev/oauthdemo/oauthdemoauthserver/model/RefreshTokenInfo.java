package com.nenashev.oauthdemo.oauthdemoauthserver.model;

import java.time.Instant;
import java.util.Objects;

import org.springframework.data.annotation.Id;

public class RefreshTokenInfo {

    @Id
    private String id;

    private String refreshToken;
    private String clientId;
    private String scope;
    private Instant issueDate;

    public RefreshTokenInfo() {
    }

    public RefreshTokenInfo(final String refreshToken,
                            final String clientId,
                            final String scope,
                            final Instant issueDate) {
        this.refreshToken = refreshToken;
        this.clientId = clientId;
        this.scope = scope;
        this.issueDate = issueDate;
    }

    public String getId() {
        return id;
    }

    public void setId(final String id) {
        this.id = id;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(final String refreshToken) {
        this.refreshToken = refreshToken;
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

    public Instant getIssueDate() {
        return issueDate;
    }

    public void setIssueDate(final Instant issueDate) {
        this.issueDate = issueDate;
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        final RefreshTokenInfo that = (RefreshTokenInfo) o;
        return Objects.equals(id, that.id) &&
            Objects.equals(refreshToken, that.refreshToken) &&
            Objects.equals(clientId, that.clientId) &&
            Objects.equals(scope, that.scope) &&
            Objects.equals(issueDate, that.issueDate);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

    @Override
    public String toString() {
        return "RefreshTokenInfo{" +
            "id='" + id + '\'' +
            ", refreshToken='" + refreshToken + '\'' +
            ", clientId='" + clientId + '\'' +
            ", scope='" + scope + '\'' +
            ", issueDate=" + issueDate +
            '}';
    }
}
