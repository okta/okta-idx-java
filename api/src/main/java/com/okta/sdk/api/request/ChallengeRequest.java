package com.okta.sdk.api.request;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.okta.sdk.api.model.Authenticator;

@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY)
public class ChallengeRequest {

    public String stateHandle;
    public Authenticator authenticator;

    public ChallengeRequest(String stateHandle, Authenticator authenticator) {
        this.stateHandle = stateHandle;
        this.authenticator = authenticator;
    }
}
