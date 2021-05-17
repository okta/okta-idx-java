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
package com.okta.spring.example.controllers;

import com.okta.commons.lang.Strings;
import com.okta.idx.sdk.api.client.IDXAuthenticationWrapper;
import com.okta.idx.sdk.api.client.ProceedContext;
import com.okta.idx.sdk.api.response.AuthenticationResponse;
import com.okta.idx.sdk.api.response.TokenResponse;
import com.okta.spring.example.helpers.HomeHelper;

import com.okta.spring.example.helpers.Util;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpSession;

@Controller
public class HomeController {

    /**
     * logger instance.
     */
    private final Logger logger = LoggerFactory.getLogger(HomeController.class);

    /**
     * The issuer url.
     */
    @Value("${okta.idx.issuer}")
    private String issuer;

    /**
     * homeHelper instance.
     */
    @Autowired
    private HomeHelper homeHelper;

    /**
     * idx authentication wrapper instance.
     */
    @Autowired
    private IDXAuthenticationWrapper authenticationWrapper;

    /**
     * Display the index page or home page (if we have obtained a token from the interaction code in callback).
     *
     * @param interactionCode the interaction code from callback (optional)
     * @param session the http session
     * @return the index page view with table of contents or the home page if we have a token.
     */
    @GetMapping("/")
    public ModelAndView displayIndexPage(final @RequestParam(name = "interaction_code", required = false) String interactionCode,
                                         final HttpSession session) {

        ProceedContext proceedContext = Util.getProceedContextFromSession(session);

        if (!Strings.hasText(interactionCode) || proceedContext == null) {
            return new ModelAndView("index");
        }

        AuthenticationResponse authenticationResponse =
                authenticationWrapper.fetchTokenWithInteractionCode(issuer, proceedContext, interactionCode);
        return homeHelper.proceedToHome(authenticationResponse.getTokenResponse(), session);
    }

    /**
     * Display the login page.
     *
     * @param session the http session
     * @return the login view
     */
    @GetMapping(value = "/login")
    public ModelAndView displayLoginPage(final HttpSession session) {
        TokenResponse tokenResponse =
                (TokenResponse) session.getAttribute("tokenResponse");

        // render token response if a successful one is already present in session
        if (tokenResponse != null) {
            return homeHelper.proceedToHome(tokenResponse, session);
        }
        return new ModelAndView("login");
    }

    /**
     * Display the login with IDP page.
     *
     * @param session the http session
     * @return the login with IDP view
     */
    @GetMapping(value = "/login-with-idp")
    public ModelAndView displayLoginWithIdpPage(final HttpSession session) {

        AuthenticationResponse authenticationResponse = authenticationWrapper.getIdps();
        Util.updateSession(session, authenticationResponse.getProceedContext());
        ModelAndView modelAndView = new ModelAndView("login-with-idp");
        modelAndView.addObject("idps", authenticationResponse.getIdps());
        return modelAndView;
    }

    /**
     * Display the forgot password page.
     *
     * @return the forgot password view
     */
    @GetMapping("/forgot-password")
    public ModelAndView displayForgotPasswordPage() {
        return new ModelAndView("forgot-password");
    }

    /**
     * Display the registration page.
     *
     * @return the register view
     */
    @GetMapping("/register")
    public ModelAndView displayRegisterPage() {
        return new ModelAndView("register");
    }

    /**
     * Display the verify email authenticator enrollment page.
     *
     * @return the verify email authenticators view
     */
    @GetMapping("/verify-email-authenticator-enrollment")
    public ModelAndView displayVerifyEmailAuthenticatorEnrollmentPage() {
        return new ModelAndView("verify-email-authenticator-enrollment");
    }

    /**
     * Display the password authenticator enrollment page.
     *
     * @return the password authenticator enrollment view
     */
    @GetMapping("/password-authenticator-enrollment")
    public ModelAndView displayPasswordAuthenticatorEnrollmentPage() {
        return new ModelAndView("password-authenticator-enrollment");
    }
}
