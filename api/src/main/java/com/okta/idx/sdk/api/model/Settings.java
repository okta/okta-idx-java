package com.okta.idx.sdk.api.model;

import java.io.Serializable;

public class Settings implements Serializable {

    private static final long serialVersionUID = -8725901106382363282L;

    private Complexity complexity;

    private Age age;

    public Complexity getComplexity() {
        return complexity;
    }

    public void setComplexity(Complexity complexity) {
        this.complexity = complexity;
    }

    public Age getAge() {
        return age;
    }

    public void setAge(Age age) {
        this.age = age;
    }
}
