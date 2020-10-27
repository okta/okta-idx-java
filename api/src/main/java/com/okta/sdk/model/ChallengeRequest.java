package com.okta.sdk.model;

import com.fasterxml.jackson.annotation.JsonAutoDetect;

@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY)
public class ChallengeRequest {

    public String stateHandle;
    public Authenticator authenticator;

    public ChallengeRequest(String stateHandle, Authenticator authenticator) {
        this.stateHandle = stateHandle;
        this.authenticator = authenticator;
    }
}
