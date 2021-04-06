package com.okta.idx.sdk.api.model;

public class AuthenticatorUIOption {

    private String id;

    private String type;

    public AuthenticatorUIOption() {}

    public AuthenticatorUIOption(String id, String type) {
        this.id = id;
        this.type = type;
    }

    public String getId() {
        return id;
    }

    public String getType() {
        return type;
    }
}
