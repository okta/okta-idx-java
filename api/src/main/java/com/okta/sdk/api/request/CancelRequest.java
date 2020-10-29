package com.okta.sdk.api.request;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY)
public class CancelRequest {

    private String stateHandle;

    public CancelRequest(String stateHandle) {
        this.stateHandle = stateHandle;
    }
}
