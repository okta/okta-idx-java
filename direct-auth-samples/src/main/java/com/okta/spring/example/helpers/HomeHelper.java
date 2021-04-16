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
package com.okta.spring.example.helpers;

import com.okta.idx.sdk.api.response.TokenResponse;
import com.okta.jwt.AccessTokenVerifier;
import com.okta.jwt.JwtVerificationException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpSession;

@Component
public class HomeHelper {
    /**
     * jwt parser instance.
     */
    @Autowired
    private AccessTokenVerifier accessTokenVerifier;

    /**
     * Go to the home page, setting the session, and creating the view.
     * @param tokenResponse
     * @param session
     * @return the ModelAndView for the home page.
     */
    public ModelAndView proceedToHome(final TokenResponse tokenResponse, final HttpSession session) {
        // success
        ModelAndView mav = new ModelAndView("home");
        mav.addObject("tokenResponse", tokenResponse);
        String user = null;
        try {
            user = (String) accessTokenVerifier.decode(tokenResponse.idToken).getClaims().get("email");
        } catch (JwtVerificationException e) {
            e.printStackTrace();
        }
        mav.addObject("user", user);

        // store token in session
        session.setAttribute("tokenResponse", tokenResponse);

        return mav;
    }
}
