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
package com.okta.spring.example.controllers;

import com.okta.commons.lang.Strings;
import com.okta.idx.sdk.api.client.Authenticator;
import com.okta.idx.sdk.api.client.IDXAuthenticationWrapper;
import com.okta.idx.sdk.api.client.ProceedContext;
import com.okta.idx.sdk.api.model.RequestContext;
import com.okta.idx.sdk.api.model.FormValue;
import com.okta.idx.sdk.api.model.VerifyAuthenticatorOptions;
import com.okta.idx.sdk.api.response.AuthenticationResponse;
import com.okta.idx.sdk.api.response.TokenResponse;
import com.okta.spring.example.helpers.HomeHelper;
import com.okta.spring.example.helpers.ResponseHandler;
import com.okta.spring.example.helpers.Util;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.util.CollectionUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import jakarta.servlet.http.HttpSession;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;

@Controller
public class HomeController {

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
     * b) home page - if the user is authenticated (or) we have obtained a token for the user from the interaction code or otp in callback.
     * c) info page - if the user is unauthenticated yet and has received an otp in callback. the info page will ask the user to input
     *                otp in the original browser to continue with the flow.
     * d) error page - if the received state does not correlate with the state in client context or if the callback
     *                 contains error parameters.
     * <p>
     * where index page refers to the root view with table of contents,
     * and home page refers to the view that shows the user profile information along with token information.
     *
     * @param interactionCode the interaction code from callback (optional)
     * @param state the state value from callback (optional)
     * @param otp the one time password or verification code (optional)
     * @param error the error from callback when interaction_code could not be sent (optional)
     * @param errDesc the error_description from callback (optional)
     * @param session the http session
     * @return the index page view with table of contents or the home page view if we have a token or the info page.
     */
    @RequestMapping(value = {"/", "**/callback"}, method = RequestMethod.GET)
    public ModelAndView displayIndexOrHomePage(final @RequestParam(name = "interaction_code", required = false) String interactionCode,
                                               final @RequestParam(name = "state", required = false) String state,
                                               final @RequestParam(name = "otp", required = false) String otp,
                                               final @RequestParam(name = "error", required = false) String error,
                                               final @RequestParam(name = "error_description", required = false) String errDesc,
                                               final HttpSession session) {

        ProceedContext proceedContext = Util.getProceedContextFromSession(session);
        TokenResponse tokenResponse = (TokenResponse) session.getAttribute("tokenResponse");

        // render home page if token is already present in session
        if (tokenResponse != null) {
            return homeHelper.proceedToHome(tokenResponse, session);
        }

        // correlate received state with the client context
        if ((Strings.hasText(interactionCode) || Strings.hasText(otp))
                && proceedContext != null
                && (Strings.isEmpty(state) || !state.equals(proceedContext.getClientContext().getState()))) {
            ModelAndView mav = new ModelAndView("error");
            mav.addObject("errors",
                    "Could not correlate client context with the received state value " + state + " in callback");
            return mav;
        }

        AuthenticationResponse authenticationResponse;

        // if interaction code is present, exchange it for a token
        if (Strings.hasText(interactionCode)) {
            authenticationResponse = authenticationWrapper.fetchTokenWithInteractionCode(proceedContext, interactionCode);
            return responseHandler.handleKnownTransitions(authenticationResponse, session);
        }

        // if otp is present, proceed with introspect to finish the flow
        if (Strings.hasText(otp)) {
            if (proceedContext == null) {
                // different browser case
                ModelAndView mav = new ModelAndView("info");
                mav.addObject("message",
                        "Please enter OTP " + otp + " in the original browser tab to finish the flow.");
                return mav;
            }

            VerifyAuthenticatorOptions verifyAuthenticatorOptions = new VerifyAuthenticatorOptions(otp);
            authenticationResponse = authenticationWrapper
                    .verifyAuthenticator(proceedContext, verifyAuthenticatorOptions);
            return responseHandler.handleKnownTransitions(authenticationResponse, session);
        }

        // if error params are present, show error page
        if (Strings.hasText(error) || Strings.hasText(errDesc)) {
            ModelAndView mav = new ModelAndView("error");
            mav.addObject("errors", error + ":" + errDesc);
            return mav;
        }

        // return the root view
        return new ModelAndView("index");
    }

    /**
     * Handle the self-service password reset (SSPR) redirect.
     *
     * @param recoveryToken the recovery token (from email link)
     * @param session the http session
     * @return the register-password view
     */
    @GetMapping(value = "/reset-password")
    public ModelAndView displayResetPasswordPage(final @RequestParam(name = "recovery_token") String recoveryToken,
                                                 final HttpSession session) {
        beginPasswordRecovery(session, recoveryToken);
        return new ModelAndView("register-password");
    }

    /**
     * Activate user with activation token.
     *
     * @param activationToken the activation token (from email link)
     * @param session the http session
     * @return the authenticator selection or home page view
     */
    @GetMapping(value = "/activate")
    public ModelAndView displayUserActivationPage(final @RequestParam(name = "token") String activationToken,
                                                  final HttpSession session) {
        beginUserActivation(session, activationToken);
        ProceedContext proceedContext = Util.getProceedContextFromSession(session);
        AuthenticationResponse authenticationResponse = authenticationWrapper.introspect(proceedContext.getClientContext());
        return responseHandler.handleKnownTransitions(authenticationResponse, session);
    }

    /**
     * Display the login page with username and password (optional).
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

        // get proceed context
        ProceedContext proceedContext = authenticationResponse.getProceedContext();

        boolean isPasswordRequired = !proceedContext.isIdentifierFirstFlow();

        if (authenticationResponse.getErrors().size() > 0) {
            ModelAndView modelAndView = new ModelAndView("error");
            modelAndView.addObject("errors", authenticationResponse.getErrors());
            return modelAndView;
        }

        ModelAndView modelAndView = new ModelAndView("login");
        if (!CollectionUtils.isEmpty(authenticationResponse.getIdps())) {
            modelAndView.addObject("idps", authenticationResponse.getIdps());
        }

        session.setAttribute("isPasswordRequired", isPasswordRequired);
        return modelAndView;
    }

    /**
     * Display the select authenticator page.
     *
     * @param session the http session
     * @param completedAuthenticatorType the last enrolled/verified authenticator type
     * @return the select authenticators view.
     */
    @GetMapping("/select-authenticator")
    public ModelAndView displaySelectAuthenticatorPage(
            final HttpSession session,
            final @RequestParam(value = "completed", required = false) String completedAuthenticatorType) {

        List<Authenticator> authenticators = (List<Authenticator>) session.getAttribute("authenticators");

        if (completedAuthenticatorType != null) {
            authenticators.removeIf(authenticator -> authenticator.getLabel().equals(completedAuthenticatorType));
        }

        TokenResponse tokenResponse = (TokenResponse) session.getAttribute("tokenResponse");
        if (tokenResponse != null) {
            return homeHelper.proceedToHome(tokenResponse, session);
        }

        ProceedContext proceedContext = Util.getProceedContextFromSession(session);
        boolean canSkip = authenticationWrapper.isSkipAuthenticatorPresent(proceedContext);

        ModelAndView modelAndView = new ModelAndView("select-authenticator");
        modelAndView.addObject("title", "Select Authenticator");
        modelAndView.addObject("canSkip", canSkip);
        modelAndView.addObject("authenticators", authenticators);
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
        AuthenticationResponse authenticationResponse = begin(session);

        authenticationResponse =
                authenticationWrapper.fetchSignUpFormValues(authenticationResponse.getProceedContext());

        ModelAndView modelAndView = new ModelAndView("register");

        if (responseHandler.needsToShowErrors(authenticationResponse)) {
            modelAndView.addObject("errors", authenticationResponse.getErrors());
            return modelAndView;
        }

        Optional<FormValue> userProfileFormValue = authenticationResponse.getFormValues()
                    .stream()
                    .filter(x -> x.getName().equals("userProfile"))
                    .findFirst();

        Optional<FormValue> credentialsFormValue = authenticationResponse.getFormValues()
                .stream()
                .filter(x -> x.getName().equals("credentials"))
                .findFirst();

        if (!userProfileFormValue.isPresent()) {
            return displayErrorPage();
        }

        List<FormValue> userProfileAttributes =
                new LinkedList<>(userProfileFormValue.get().form().getValue());

        if (!CollectionUtils.isEmpty(userProfileAttributes)) {
            modelAndView.addObject("userProfileAttributes", userProfileAttributes);
        }

        if (credentialsFormValue.isPresent()) {
            modelAndView.addObject("credentialsRequired", true);
        }

        return modelAndView;
    }

    /**
     * Display the custom sec qn registration page.
     *
     * @return the custom sec qn registration page view
     */
    @GetMapping("/register-custom-sec-qn")
    public ModelAndView displayCustomSecQnPage() {
        ModelAndView modelAndView = new ModelAndView("register-custom-sec-qn");
        modelAndView.addObject("title", "Custom Security Question");
        return new ModelAndView();
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
        final RequestContext requestContext = Util.constructRequestContext();
        AuthenticationResponse authenticationResponse = authenticationWrapper.begin(requestContext);
        Util.updateSession(session, authenticationResponse.getProceedContext());
        return authenticationResponse;
    }

    private AuthenticationResponse beginPasswordRecovery(final HttpSession session, String recoveryToken) {
        final RequestContext requestContext = Util.constructRequestContext();
        AuthenticationResponse authenticationResponse = authenticationWrapper.beginPasswordRecovery(recoveryToken, requestContext);
        Util.updateSession(session, authenticationResponse.getProceedContext());
        return authenticationResponse;
    }

    private AuthenticationResponse beginUserActivation(final HttpSession session, String activationToken) {
        final RequestContext requestContext = Util.constructRequestContext();
        AuthenticationResponse authenticationResponse = authenticationWrapper.beginUserActivation(activationToken, requestContext);
        Util.updateSession(session, authenticationResponse.getProceedContext());
        return authenticationResponse;
    }
}
