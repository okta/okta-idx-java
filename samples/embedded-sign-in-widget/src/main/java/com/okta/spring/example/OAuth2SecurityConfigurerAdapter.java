/*
 * Copyright (c) 2021-Present, Okta, Inc.
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
package com.okta.spring.example;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;

@Configuration
public class OAuth2SecurityConfigurerAdapter {

    @Autowired
    private ClientRegistrationRepository clientRegistrationRepository;

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
                .exceptionHandling(ex -> ex.accessDeniedHandler((req, res, e) -> res.sendRedirect("/403")))
                .addFilterBefore(customAuthenticationProcessingFilter(http), OAuth2LoginAuthenticationFilter.class)
                .authorizeHttpRequests((authz) -> authz
                        .requestMatchers("/logout").permitAll()
                        .requestMatchers("/home").permitAll()
                        .requestMatchers("/hello").permitAll()
                        .anyRequest().authenticated()
                )
                .logout((logout) -> logout.logoutSuccessUrl("/"))
                .oauth2Client(Customizer.withDefaults())
                .oauth2Login(r -> r.redirectionEndpoint(re -> re.baseUri("/authorization-code/callback*")));

        return http.build();
    }

    @Bean
    public CustomAuthenticationProcessingFilter customAuthenticationProcessingFilter(HttpSecurity httpSecurity) throws Exception {
        CustomAuthenticationProcessingFilter customAuthenticationProcessingFilter =
                new CustomAuthenticationProcessingFilter("/authorization-code/callback",
                        authenticationManager(httpSecurity.getSharedObject(AuthenticationConfiguration.class)));
        customAuthenticationProcessingFilter.setAuthenticationDetailsSource(new WebAuthenticationDetailsSource());
        customAuthenticationProcessingFilter.setClientRegistrationRepository(clientRegistrationRepository);
        return customAuthenticationProcessingFilter;
    }
}
