package com.okta.sdk.api.request;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.okta.sdk.api.model.Credentials;

@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY)
public class AnswerChallengeRequest {

    public String stateHandle;

    public Credentials credentials;

    public AnswerChallengeRequest(String stateHandle, Credentials credentials) {
        this.stateHandle = stateHandle;
        this.credentials = credentials;
    }
}
