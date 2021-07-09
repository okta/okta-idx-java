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
package com.okta.spring.example.helpers;

import com.okta.commons.lang.Assert;
import com.okta.idx.sdk.api.response.TokenResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpSession;
import java.util.LinkedHashMap;
import java.util.Map;

import static com.okta.idx.sdk.api.util.ClientUtil.getNormalizedUri;

@Component
public class HomeHelper {

    /**
     * logger instance.
     */
    private final Logger logger = LoggerFactory.getLogger(HomeHelper.class);

    /**
     * The issuer url.
     */
    @Value("${okta.idx.issuer}")
    private String issuer;

    /**
     * rest template.
     */
    @Autowired
    private RestTemplate restTemplate;

    /**
     * Go to the home page, setting the session, and creating the view.
     * @param tokenResponse the token response reference
     * @param session the http session object
     * @return the ModelAndView for the home page.
     */
    public ModelAndView proceedToHome(final TokenResponse tokenResponse, final HttpSession session) {

        Map<String, String> claims = new LinkedHashMap<>();

        // success
        ModelAndView mav = new ModelAndView("home");
        mav.addObject("tokenResponse", tokenResponse);

        String user = null;

        try {
            // get user claim info from /v1/userinfo endpoint
            String userInfoUrl = getNormalizedUri(issuer, "/v1/userinfo");

            HttpHeaders httpHeaders = new HttpHeaders();
            httpHeaders.setBearerAuth(tokenResponse.getAccessToken());

            HttpEntity<String> requestEntity = new HttpEntity<>(null, httpHeaders);

            ParameterizedTypeReference<Map<String, String>> responseType =
                    new ParameterizedTypeReference<Map<String, String>>() { };
            ResponseEntity<Map<String, String>> responseEntity =
                    restTemplate.exchange(userInfoUrl, HttpMethod.GET, requestEntity, responseType);

            claims = responseEntity.getBody();
            Assert.notNull(claims, "claims cannot be null");
            user = claims.get("preferred_username");
        } catch (Exception e) {
            logger.error("Error retrieving profile from user info endpoint", e);
        }
        mav.addObject("user", user);
        mav.addObject("claims", claims);

        // store token in session
        session.setAttribute("tokenResponse", tokenResponse);

        return mav;
    }
}
