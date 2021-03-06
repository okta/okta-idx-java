/*
 * Copyright (c) 2020-Present, Okta, Inc.
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
package com.okta.idx.sdk.api.response;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonAutoDetect;

@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY)
public class TokenResponse {

    /**
     * The Access Token JWT
     */
    @JsonAlias("access_token")
    public String accessToken;

    /**
     * Seconds the token is valid for
     */
    @JsonAlias("expires_in")
    public Integer expiresIn;

    /**
     * The ID Token JWT
     */
    @JsonAlias("id_token")
    public String idToken;

    /**
     * The Refresh Token JWT
     */
    @JsonAlias("refresh_token")
    public String refreshToken;

    /**
     * The scope of the JWT
     */
    public String scope;

    /**
     * The type of Token the JWT is
     */
    @JsonAlias("token_type")
    public String tokenType;

    public String getAccessToken() {
        return accessToken;
    }

    public Integer getExpiresIn() {
        return expiresIn;
    }

    public String getIdToken() {
        return idToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public String getScope() {
        return scope;
    }

    public String getTokenType() {
        return tokenType;
    }
}
