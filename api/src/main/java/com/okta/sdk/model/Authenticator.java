package com.okta.sdk.model;

import com.fasterxml.jackson.annotation.JsonAutoDetect;

@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY)
public class Authenticator {

    private String id;

    private String methodType;

    public Authenticator(String id, String methodType) {
        this.id = id;
        this.methodType = methodType;
    }
}
