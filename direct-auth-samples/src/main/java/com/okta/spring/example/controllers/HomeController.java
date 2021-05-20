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
import com.okta.spring.example.helpers.ResponseHandler;
import com.okta.spring.example.helpers.Util;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.util.CollectionUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpSession;

@Controller
public class HomeController {

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
     * homeHelper instance.
     */
    @Autowired
    private ResponseHandler responseHandler;

    /**
     * idx authentication wrapper instance.
     */
    @Autowired
    private IDXAuthenticationWrapper authenticationWrapper;

    /**
     * Display one of:
     * <p>
     * a) index page - if the user is not authenticated yet (does not have token response in session).
     * b) home page - if the user is authenticated (or) we have obtained a token for the user from the interaction code in callback.
     * <p>
     * where index page refers to the root view with table of contents,
     * and home page refers to the view that shows the user profile information along with token information.
     *
     * @param interactionCode the interaction code from callback (optional)
     * @param state the state value from callback (optional)
     * @param error the error from callback when interaction_code could not be sent (optional)
     * @param errorDescription the error_description from callback (optional)
     * @param session the http session
     * @return the index page view with table of contents or the home page view if we have a token.
     */
    @GetMapping("/")
    public ModelAndView displayIndexOrHomePage(final @RequestParam(name = "interaction_code", required = false) String interactionCode,
                                               final @RequestParam(name = "state", required = false) String state,
                                               final @RequestParam(name = "error", required = false) String error,
                                               final @RequestParam(name = "error_description", required = false) String errorDescription,
                                               final HttpSession session) {

        ProceedContext proceedContext = Util.getProceedContextFromSession(session);
        TokenResponse tokenResponse = (TokenResponse) session.getAttribute("tokenResponse");

        // render home page if token is already present in session
        if (tokenResponse != null) {
            return homeHelper.proceedToHome(tokenResponse, session);
        }

//        if (Strings.hasText(error) && error.equals("interaction_required")) {
//            AuthenticationResponse authenticationResponse =
//                    authenticationWrapper.introspect(proceedContext.getClientContext());
//            return responseHandler.handleKnownTransitions(authenticationResponse, session);
//        }

        // if interaction code is received in callback, exchange it for a token
        if (Strings.hasText(interactionCode)) {
            // validate state param
            if (Strings.isEmpty(state) || !state.equals(proceedContext.getClientContext().getState())) {
                ModelAndView mav = new ModelAndView("error");
                mav.addObject("errors", "Could not correlate received 'state' value in callback");
                return mav;
            }

            AuthenticationResponse authenticationResponse =
                    authenticationWrapper.fetchTokenWithInteractionCode(issuer, proceedContext, interactionCode);

            return responseHandler.handleKnownTransitions(authenticationResponse, session);
        }

        // if error is received in callback, show error page
        if (Strings.hasText(error)) {
            ModelAndView mav = new ModelAndView("error");
            mav.addObject("errors", errorDescription);
            return mav;
        }

        // none of the above cases hold good, so return to root view
        return new ModelAndView("index");
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

        AuthenticationResponse authenticationResponse = begin(session);
        ModelAndView modelAndView = new ModelAndView("login");
        if (!CollectionUtils.isEmpty(authenticationResponse.getIdps())) {
            modelAndView.addObject("idps", authenticationResponse.getIdps());
        }
        return modelAndView;
    }

    /**
     * Display the forgot password page.
     *
     * @param session the http session
     * @return the forgot password view
     */
    @GetMapping("/forgot-password")
    public ModelAndView displayForgotPasswordPage(final HttpSession session) {
        begin(session);
        return new ModelAndView("forgot-password");
    }

    /**
     * Display the registration page.
     *
     * @param session the http session
     * @return the register view
     */
    @GetMapping("/register")
    public ModelAndView displayRegisterPage(final HttpSession session) {
        begin(session);
        return new ModelAndView("register");
    }

    /**
     * Display the error page.
     *
     * @return the error page view
     */
    @GetMapping("/error")
    public ModelAndView displayErrorPage() {
        return new ModelAndView("error");
    }

    private AuthenticationResponse begin(final HttpSession session) {
        AuthenticationResponse authenticationResponse = authenticationWrapper.begin();
        Util.updateSession(session, authenticationResponse.getProceedContext());
        return authenticationResponse;
    }
}
