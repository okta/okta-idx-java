/*
 * Copyright 2021-Present Okta, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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
