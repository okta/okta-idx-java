package com.okta.idx.sdk.api.model;

public enum AuthenticationStatus {

    SUCCESS("success"),

    PASSWORD_EXPIRED("password_expired"),

    UNKNOWN("unknown");

    private String value;

    AuthenticationStatus(String value) {
        this.value = value;
    }

    @Override
    public String toString() {
        return String.valueOf(value);
    }
}
