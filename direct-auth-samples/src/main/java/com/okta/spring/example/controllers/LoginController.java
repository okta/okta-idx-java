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

import com.okta.commons.lang.Assert;
import com.okta.commons.lang.Strings;
import com.okta.idx.sdk.api.client.Authenticator;
import com.okta.idx.sdk.api.client.IDXAuthenticationWrapper;
import com.okta.idx.sdk.api.client.ProceedContext;
import com.okta.idx.sdk.api.model.AuthenticationOptions;
import com.okta.idx.sdk.api.model.UserProfile;
import com.okta.idx.sdk.api.model.VerifyAuthenticatorOptions;
import com.okta.idx.sdk.api.response.AuthenticationResponse;
import com.okta.spring.example.helpers.ResponseHandler;
import com.okta.spring.example.helpers.Util;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpSession;
import java.util.List;

@Controller
public class LoginController {

    /**
     * logger instance.
     */
    private final Logger logger = LoggerFactory.getLogger(LoginController.class);

    /**
     * idx authentication wrapper instance.
     */
    @Autowired
    private IDXAuthenticationWrapper idxAuthenticationWrapper;

    /**
     * response handler.
     */
    @Autowired
    private ResponseHandler responseHandler;

    /**
     * Handle login with the supplied username and password.
     *
     * @param username the username
     * @param password the password
     * @param session the session
     * @return the home page view (if login is successful), else the login page with errors.
     */
    @PostMapping("/login")
    public ModelAndView login(final @RequestParam("username") String username,
                              final @RequestParam("password") String password,
                              final HttpSession session) {

        ProceedContext proceedContext = Util.getProceedContextFromSession(session);

        // trigger authentication
        AuthenticationResponse authenticationResponse =
                idxAuthenticationWrapper.authenticate(new AuthenticationOptions(username, password), proceedContext);

        if (responseHandler.needsToShowErrors(authenticationResponse)) {
            ModelAndView modelAndView = new ModelAndView("login");
            modelAndView.addObject("errors", authenticationResponse.getErrors());
            return modelAndView;
        }

        return responseHandler.handleKnownTransitions(authenticationResponse, session);
    }

    /**
     * Handle forgot password (password recovery) functionality.
     *
     * @param username the username
     * @param session the session
     * @return the verify view (if password recovery operation is successful),
     * else the forgot password page with errors.
     */
    @PostMapping("/forgot-password")
    public ModelAndView forgotPassword(final @RequestParam("username") String username,
                                       final HttpSession session) {
        logger.info(":: Forgot Password ::");

        ProceedContext proceedContext = Util.getProceedContextFromSession(session);

        AuthenticationResponse authenticationResponse =
                idxAuthenticationWrapper.recoverPassword(username, proceedContext);

        if (responseHandler.needsToShowErrors(authenticationResponse)) {
            ModelAndView modelAndView = new ModelAndView("forgot-password");
            modelAndView.addObject("errors", authenticationResponse.getErrors());
            return modelAndView;
        }

        return responseHandler.handleKnownTransitions(authenticationResponse, session);
    }

    /**
     * Handle authenticator selection during authentication.
     *
     * @param authenticatorType the authenticatorType
     * @param session the session
     * @param action the submit or cancel action from form post
     * @return select authenticator view or select factor view or error view
     */
    @PostMapping(value = "/select-authenticator")
    public ModelAndView selectAuthenticator(final @RequestParam("authenticator-type") String authenticatorType,
                                            final @RequestParam(value = "action") String action,
                                            final HttpSession session) {

        ProceedContext proceedContext = Util.getProceedContextFromSession(session);

        AuthenticationResponse authenticationResponse = null;

        if ("skip".equals(action)) {
            logger.info("Skipping {} authenticator", authenticatorType);
            authenticationResponse = idxAuthenticationWrapper.skipAuthenticatorEnrollment(proceedContext);
            return responseHandler.handleKnownTransitions(authenticationResponse, session);
        }

        Authenticator foundAuthenticator = null;

        List<Authenticator> authenticators = (List<Authenticator>) session.getAttribute("authenticators");

        for (Authenticator authenticator : authenticators) {
            if (authenticatorType.equals(authenticator.getLabel())) {
                foundAuthenticator = authenticator;

                if (foundAuthenticator.getFactors().size() == 1) {
                    authenticationResponse = idxAuthenticationWrapper.selectAuthenticator(proceedContext, authenticator);
                } else {
                    // user should select the factor in a separate view
                    ModelAndView modelAndView = new ModelAndView("select-factor");
                    modelAndView.addObject("title", "Select Factor");
                    modelAndView.addObject("authenticatorId", foundAuthenticator.getId());
                    modelAndView.addObject("factors", foundAuthenticator.getFactors());
                    return modelAndView;
                }
            }
        }

        if (responseHandler.needsToShowErrors(authenticationResponse)) {
            ModelAndView modelAndView = new ModelAndView("select-authenticator");
            modelAndView.addObject("errors", authenticationResponse.getErrors());
            return modelAndView;
        }

        ModelAndView terminalTransition = responseHandler.handleTerminalTransitions(authenticationResponse, session);
        if (terminalTransition != null) {
            return terminalTransition;
        }

        switch (authenticationResponse.getAuthenticationStatus()) {
            case AWAITING_AUTHENTICATOR_VERIFICATION_DATA:
                return responseHandler.verifyForm();
            case AWAITING_AUTHENTICATOR_ENROLLMENT:
            case AWAITING_AUTHENTICATOR_ENROLLMENT_DATA:
                return responseHandler.registerVerifyForm(foundAuthenticator);
            default:
                return responseHandler.handleKnownTransitions(authenticationResponse, session);
        }
    }

    /**
     * Handle factor selection during authentication.
     *
     * @param authenticatorId the authenticator ID of selected authenticator
     * @param mode the sms or voice factor mode
     * @param session the session
     * @return the view associated with authentication response.
     */
    @PostMapping("/select-factor")
    public ModelAndView selectFactor(final @RequestParam("authenticatorId") String authenticatorId,
                                     final @RequestParam("mode") String mode,
                                     final HttpSession session) {

        ProceedContext proceedContext = Util.getProceedContextFromSession(session);

        List<Authenticator> authenticators = (List<Authenticator>) session.getAttribute("authenticators");

        Authenticator foundAuthenticator = null;

        for (Authenticator auth : authenticators) {
            if (auth.getId().equals(authenticatorId)) {
                foundAuthenticator = auth;
            }
        }

        Assert.notNull(foundAuthenticator, "Authenticator not found");

        AuthenticationResponse authenticationResponse = null;
        Authenticator.Factor foundFactor = null;

        for (Authenticator.Factor factor : foundAuthenticator.getFactors()) {
            if (factor.getMethod().equals(mode)) {
                foundFactor = factor;
                authenticationResponse = idxAuthenticationWrapper.selectFactor(proceedContext, foundFactor);
                break;
            }
        }

        Assert.notNull(foundFactor, "Factor not found");

        ModelAndView terminalTransition = responseHandler.handleTerminalTransitions(authenticationResponse, session);
        if (terminalTransition != null) {
            return terminalTransition;
        }

        switch (authenticationResponse.getAuthenticationStatus()) {
            case AWAITING_AUTHENTICATOR_VERIFICATION_DATA:
                return responseHandler.verifyForm();
            case AWAITING_AUTHENTICATOR_ENROLLMENT:
            case AWAITING_AUTHENTICATOR_ENROLLMENT_DATA:
                return responseHandler.registerVerifyForm(foundFactor);
            default:
                return responseHandler.handleKnownTransitions(authenticationResponse, session);
        }
    }

    /**
     * Handle authenticator verification functionality.
     *
     * @param code    the verification code
     * @param session the session
     * @return the view associated with authentication response.
     */
    @PostMapping("/verify")
    public ModelAndView verify(final @RequestParam("code") String code,
                               final HttpSession session) {
        logger.info(":: Verify Code :: {}", code);

        ProceedContext proceedContext = Util.getProceedContextFromSession(session);

        VerifyAuthenticatorOptions verifyAuthenticatorOptions = new VerifyAuthenticatorOptions(code);

        AuthenticationResponse authenticationResponse =
                idxAuthenticationWrapper.verifyAuthenticator(proceedContext, verifyAuthenticatorOptions);

        if (responseHandler.needsToShowErrors(authenticationResponse)) {
            ModelAndView modelAndView = new ModelAndView("verify");
            modelAndView.addObject("errors", authenticationResponse.getErrors());
            return modelAndView;
        }

        return responseHandler.handleKnownTransitions(authenticationResponse, session);
    }

    /**
     * Handle change password functionality.
     *
     * @param newPassword the new password
     * @param confirmNewPassword the confirmation of the new password
     * @param session the session
     * @return the view associated with authentication response.
     */
    @PostMapping("/register-password")
    public ModelAndView registerPassword(final @RequestParam("new-password") String newPassword,
                                         final @RequestParam("confirm-new-password") String confirmNewPassword,
                                         final HttpSession session) {
        logger.info(":: Change Password ::");

        if (!newPassword.equals(confirmNewPassword)) {
            ModelAndView mav = new ModelAndView("register-password");
            mav.addObject("errors", "Passwords do not match");
            return mav;
        }

        ProceedContext proceedContext = Util.getProceedContextFromSession(session);

        VerifyAuthenticatorOptions verifyAuthenticatorOptions = new VerifyAuthenticatorOptions(newPassword);
        AuthenticationResponse authenticationResponse =
                idxAuthenticationWrapper.verifyAuthenticator(proceedContext, verifyAuthenticatorOptions);

        if (responseHandler.needsToShowErrors(authenticationResponse)) {
            ModelAndView modelAndView = new ModelAndView("register-password");
            modelAndView.addObject("errors", authenticationResponse.getErrors());
            return modelAndView;
        }

        return responseHandler.handleKnownTransitions(authenticationResponse, session);
    }

    /**
     * Handle new user registration functionality.
     *
     * @param lastname the lastname
     * @param firstname the firstname
     * @param email the email
     * @param session the session
     * @return the enroll authenticators view.
     */
    @PostMapping("/register")
    public ModelAndView register(final @RequestParam("lastname") String lastname,
                                 final @RequestParam("firstname") String firstname,
                                 final @RequestParam("email") String email,
                                 final HttpSession session) {
        logger.info(":: Register ::");

        ProceedContext beginProceedContext = Util.getProceedContextFromSession(session);
        AuthenticationResponse newUserRegistrationResponse = idxAuthenticationWrapper.fetchSignUpFormValues(beginProceedContext);

        if (responseHandler.needsToShowErrors(newUserRegistrationResponse)) {
            ModelAndView mav = new ModelAndView("register");
            mav.addObject("errors", newUserRegistrationResponse.getErrors());
            return mav;
        }

        UserProfile userProfile = new UserProfile();
        userProfile.addAttribute("lastName", lastname);
        userProfile.addAttribute("firstName", firstname);
        userProfile.addAttribute("email", email);

        ProceedContext proceedContext = newUserRegistrationResponse.getProceedContext();

        AuthenticationResponse authenticationResponse =
                idxAuthenticationWrapper.register(proceedContext, userProfile);

        if (responseHandler.needsToShowErrors(authenticationResponse)) {
            ModelAndView modelAndView = new ModelAndView("register");
            modelAndView.addObject("errors", authenticationResponse.getErrors());
            return modelAndView;
        }

        return responseHandler.handleKnownTransitions(authenticationResponse, session);
    }

    /**
     * Handle phone authenticator enrollment functionality.
     *
     * @param phone the phone number
     * @param mode the delivery mode - sms or voice
     * @param session the session
     * @return the view associated with authentication response.
     */
    @PostMapping(value = "/register-phone")
    public ModelAndView registerPhone(final @RequestParam("phone") String phone,
                                      final @RequestParam(value = "mode", required = false) String mode,
                                      final HttpSession session) {
        logger.info(":: Enroll Phone Authenticator ::");

        if (!Strings.hasText(phone)) {
            ModelAndView mav = new ModelAndView("register-phone");
            mav.addObject("errors", "Phone is required");
            return mav;
        }

        if (!Strings.hasText(mode)) {
            ModelAndView modelAndView = new ModelAndView("select-phone-factor");
            modelAndView.addObject("phone", phone);
            return modelAndView;
        }

        ProceedContext proceedContext = Util.getProceedContextFromSession(session);

        AuthenticationResponse authenticationResponse =
                idxAuthenticationWrapper.submitPhoneAuthenticator(proceedContext,
                        phone, getFactorFromMethod(session, mode));

        if (responseHandler.needsToShowErrors(authenticationResponse)) {
            ModelAndView modelAndView = new ModelAndView("register-phone");
            modelAndView.addObject("mode", mode);
            modelAndView.addObject("errors", authenticationResponse.getErrors());
            return modelAndView;
        }

        ModelAndView terminalTransition = responseHandler.handleTerminalTransitions(authenticationResponse, session);
        if (terminalTransition != null) {
            return terminalTransition;
        }

        return responseHandler.verifyForm();
    }

    /**
     * Fetch the factor associated with factor method.
     * @param session the http session
     * @param method the factor method
     * @return the factor associated with the supplied factor method.
     * @throws {@link IllegalArgumentException} if factor could not be found.
     */
    private Authenticator.Factor getFactorFromMethod(final HttpSession session,
                                                     final String method) {
        List<Authenticator> authenticators = (List<Authenticator>) session.getAttribute("authenticators");
        for (Authenticator authenticator : authenticators) {
            for (Authenticator.Factor factor : authenticator.getFactors()) {
                if (factor.getMethod().equals(method)) {
                    return factor;
                }
            }
        }
        throw new IllegalStateException("Factor not found: " + method);
    }
}
