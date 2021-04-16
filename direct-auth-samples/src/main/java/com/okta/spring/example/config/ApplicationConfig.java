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
package com.okta.spring.example.config;

import com.okta.idx.sdk.api.client.Clients;
import com.okta.idx.sdk.api.client.IDXClient;
import com.okta.jwt.AccessTokenVerifier;
import com.okta.jwt.JwtVerifiers;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ApplicationConfig {

    /**
     * The IDX client bean definition.
     *
     * @return the idx client
     */
    @Bean
    public IDXClient idxClient() {
        return Clients.builder().build();
    }

    /**
     * The accessTokenVerifier bean definition.
     *
     * @return the accessTokenVerifier
     */
    @Bean
    public AccessTokenVerifier accessTokenVerifier() {
        return JwtVerifiers.accessTokenVerifierBuilder()
                .setIssuer("https://{your_okta_domain}/oauth2/default")
                .setAudience("{your_client_id}")
                .build();
    }
}
