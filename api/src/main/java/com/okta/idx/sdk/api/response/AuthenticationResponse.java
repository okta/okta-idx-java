package com.okta.idx.sdk.api.response;

import com.okta.idx.sdk.api.model.AuthenticationStatus;
import com.okta.idx.sdk.api.model.IDXClientContext;

import java.util.LinkedList;
import java.util.List;

public class AuthenticationResponse {

    private TokenResponse tokenResponse;

    private IDXClientContext idxClientContext;

    private AuthenticationStatus authenticationStatus;

    private List<String> errors;

    public TokenResponse getTokenResponse() {
        return tokenResponse;
    }

    public void setTokenResponse(TokenResponse tokenResponse) {
        this.tokenResponse = tokenResponse;
    }

    public IDXClientContext getIdxClientContext() {
        return idxClientContext;
    }

    public void setIdxClientContext(IDXClientContext idxClientContext) {
        this.idxClientContext = idxClientContext;
    }

    public AuthenticationStatus getAuthenticationStatus() {
        return authenticationStatus;
    }

    public void setAuthenticationStatus(AuthenticationStatus authenticationStatus) {
        this.authenticationStatus = authenticationStatus;
    }

    public List<String> getErrors() {
        return errors;
    }

    public void setErrors(List<String> errors) {
        this.errors = errors;
    }

    public boolean addError(String error) {
        if (getErrors() == null) {
            this.errors = new LinkedList<>();
            return this.errors.add(error);
        }
        return getErrors().add(error);
    }
}
