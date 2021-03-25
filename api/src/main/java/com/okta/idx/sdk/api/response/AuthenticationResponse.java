package com.okta.idx.sdk.api.response;

import java.util.LinkedList;
import java.util.List;

public class AuthenticationResponse {

    private TokenResponse tokenResponse;

    private List<String> errors;

    public boolean isSuccess() {
        return tokenResponse != null;
    }

    public TokenResponse getTokenResponse() {
        return tokenResponse;
    }

    public void setTokenResponse(TokenResponse tokenResponse) {
        this.tokenResponse = tokenResponse;
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
