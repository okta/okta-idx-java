package com.okta.sdk.model;

import com.fasterxml.jackson.annotation.JsonAutoDetect;

@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY)
public class AnswerChallengeRequest {

    public String stateHandle;

    public Credentials credentials;

    public AnswerChallengeRequest(String stateHandle, Credentials credentials) {
        this.stateHandle = stateHandle;
        this.credentials = credentials;
    }
}
