package com.okta.sdk.model;

import com.fasterxml.jackson.annotation.JsonAutoDetect;

@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY)
public class IdentifyRequest {

    public IdentifyRequest(String identifier, String stateHandle, boolean rememberMe) {
        this.identifier = identifier;
        this.stateHandle = stateHandle;
        this.rememberMe = rememberMe;
    }

    public IdentifyRequest(String stateHandle, boolean rememberMe) {
        this.stateHandle = stateHandle;
        this.rememberMe = rememberMe;
    }

    private String identifier; // optional

    private String stateHandle;

    private boolean rememberMe;

    public String getIdentifier() {
        return identifier;
    }

    public void setIdentifier(String identifier) {
        this.identifier = identifier;
    }

    public String getStateHandle() {
        return stateHandle;
    }

    public void setStateHandle(String stateHandle) {
        this.stateHandle = stateHandle;
    }

    public boolean isRememberMe() {
        return rememberMe;
    }

    public void setRememberMe(boolean rememberMe) {
        this.rememberMe = rememberMe;
    }
}
