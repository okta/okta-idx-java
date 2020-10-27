package com.okta.sdk.model;

import com.fasterxml.jackson.annotation.JsonAutoDetect;

@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY)
public class IntrospectRequest {

    private String stateHandle;

    public IntrospectRequest(String stateHandle) {
        this.stateHandle = stateHandle;
    }
}
