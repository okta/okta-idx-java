package com.okta.idx.sdk.api.model;

import java.io.Serializable;

public class Complexity implements Serializable {

    private static final long serialVersionUID = -7803427477560695979L;

    private int minLength;

    private int minLowerCase;

    private int minUpperCase;

    private int minNumber;

    private int minSymbol;

    private boolean excludeUsername;

    private String[] excludeAttributes;

    public int getMinLength() {
        return minLength;
    }

    public void setMinLength(int minLength) {
        this.minLength = minLength;
    }

    public int getMinLowerCase() {
        return minLowerCase;
    }

    public void setMinLowerCase(int minLowerCase) {
        this.minLowerCase = minLowerCase;
    }

    public int getMinUpperCase() {
        return minUpperCase;
    }

    public void setMinUpperCase(int minUpperCase) {
        this.minUpperCase = minUpperCase;
    }

    public int getMinNumber() {
        return minNumber;
    }

    public void setMinNumber(int minNumber) {
        this.minNumber = minNumber;
    }

    public int getMinSymbol() {
        return minSymbol;
    }

    public void setMinSymbol(int minSymbol) {
        this.minSymbol = minSymbol;
    }

    public boolean isExcludeUsername() {
        return excludeUsername;
    }

    public void setExcludeUsername(boolean excludeUsername) {
        this.excludeUsername = excludeUsername;
    }

    public Object getExcludeAttributes() {
        return excludeAttributes;
    }

    public void setExcludeAttributes(String[] excludeAttributes) {
        this.excludeAttributes = excludeAttributes;
    }
}
