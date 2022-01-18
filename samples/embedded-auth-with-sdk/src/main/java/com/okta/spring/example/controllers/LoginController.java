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

import com.okta.commons.lang.Assert;
import com.okta.commons.lang.Strings;
import com.okta.idx.sdk.api.client.Authenticator;
import com.okta.idx.sdk.api.client.IDXAuthenticationWrapper;
import com.okta.idx.sdk.api.client.ProceedContext;
import com.okta.idx.sdk.api.model.AuthenticationOptions;
import com.okta.idx.sdk.api.model.ContextualData;
import com.okta.idx.sdk.api.model.FormValue;
import com.okta.idx.sdk.api.model.Qrcode;
import com.okta.idx.sdk.api.model.UserProfile;
import com.okta.idx.sdk.api.model.VerifyAuthenticatorOptions;
import com.okta.idx.sdk.api.model.VerifyChannelDataOptions;
import com.okta.idx.sdk.api.request.WebAuthnRequest;
import com.okta.idx.sdk.api.response.AuthenticationResponse;
import com.okta.spring.example.helpers.ResponseHandler;
import com.okta.spring.example.helpers.Util;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpSession;
import java.util.List;
import java.util.Optional;

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

        // begin transaction
        AuthenticationResponse beginResponse = idxAuthenticationWrapper.begin();

        // get proceed context
        ProceedContext proceedContext = beginResponse.getProceedContext();

        // trigger authentication
        AuthenticationResponse authenticationResponse =
                idxAuthenticationWrapper.authenticate(new AuthenticationOptions(username, password.toCharArray()), proceedContext);

        if (responseHandler.needsToShowErrors(authenticationResponse)) {
            ModelAndView modelAndView = new ModelAndView("redirect:/login");
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
        List<Authenticator> authenticators = (List<Authenticator>) session.getAttribute("authenticators");
        if (authenticatorType != null && authenticatorType.equals("webauthn")) {
            ModelAndView modelAndView;

            Optional<Authenticator> authenticatorOptional =
                    authenticators.stream().filter(auth -> auth.getType().equals(authenticatorType)).findFirst();
            String authId = authenticatorOptional.get().getId();

            AuthenticationResponse enrollResponse = idxAuthenticationWrapper.enrollAuthenticator(proceedContext, authId);

            Util.updateSession(session, enrollResponse.getProceedContext());

            String webauthnCredentialId = enrollResponse.getWebAuthnParams().getWebauthnCredentialId();

            if (webauthnCredentialId != null) {
                modelAndView = new ModelAndView("select-webauthn-authenticator");
                modelAndView.addObject("title", "Select Webauthn Authenticator");
                modelAndView.addObject("webauthnCredentialId", webauthnCredentialId);
                modelAndView.addObject("challengeData", enrollResponse.getWebAuthnParams()
                        .getCurrentAuthenticator().getValue().getContextualData().getChallengeData());
            } else {
                modelAndView = new ModelAndView("enroll-webauthn-authenticator");
                modelAndView.addObject("title", "Enroll Webauthn Authenticator");
                modelAndView.addObject("currentAuthenticator",
                        enrollResponse.getWebAuthnParams().getCurrentAuthenticator());
            }
            return modelAndView;
        }

        AuthenticationResponse authenticationResponse = null;

        if ("skip".equals(action)) {
            logger.info("Skipping {} authenticator", authenticatorType);
            authenticationResponse = idxAuthenticationWrapper.skipAuthenticatorEnrollment(proceedContext);
            return responseHandler.handleKnownTransitions(authenticationResponse, session);
        }

        Authenticator foundAuthenticator = null;

        for (Authenticator authenticator : authenticators) {
            if (authenticatorType.equals(authenticator.getType())) {
                foundAuthenticator = authenticator;

                if (foundAuthenticator.getFactors().size() == 1) {
                    authenticationResponse = idxAuthenticationWrapper.selectAuthenticator(proceedContext, authenticator);
                    Optional.ofNullable(authenticationResponse.getContextualData())
                            .ifPresent(contextualData -> session.setAttribute("totp", contextualData));
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
            case AWAITING_POLL_ENROLLMENT:
                return responseHandler.setupOktaVerifyForm(session);
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
                Optional.ofNullable(authenticationResponse.getContextualData())
                        .map(ContextualData::getQrcode)
                        .map(Qrcode::getHref)
                        .ifPresent(qrCode -> {
                            session.setAttribute("qrCode", qrCode);
                            session.setAttribute("channelName", "qrcode");
                        });
                if ("totp".equals(foundFactor.getMethod())) {
                    session.setAttribute("totp", "totp");
                }
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
            case AWAITING_CHANNEL_DATA_ENROLLMENT:
                return responseHandler.oktaVerifyViaChannelDataForm(foundFactor, session);
            case AWAITING_POLL_ENROLLMENT:
                return responseHandler.setupOktaVerifyForm(session);
            case AWAITING_CHALLENGE_POLL:
                return responseHandler.oktaVerifyChallenge(authenticationResponse);
            default:
                return responseHandler.handleKnownTransitions(authenticationResponse, session);
        }
    }

    /**
     * Show authenticator verification form.
     *
     * @return verify.html.
     */
    @GetMapping("/verify")
    public ModelAndView verify() {
        logger.info(":: Show Verify form ::");
        return new ModelAndView("verify");
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

        AuthenticationResponse authenticationResponse;
        if ("totp".equals(String.valueOf(session.getAttribute("totp")))) {
            authenticationResponse = idxAuthenticationWrapper
                    .verifyAuthenticator(proceedContext, new VerifyChannelDataOptions("totp", code));
            session.removeAttribute("totp");
        } else {
            VerifyAuthenticatorOptions verifyAuthenticatorOptions = new VerifyAuthenticatorOptions(code);
            authenticationResponse = idxAuthenticationWrapper
                    .verifyAuthenticator(proceedContext, verifyAuthenticatorOptions);
        }

        if (responseHandler.needsToShowErrors(authenticationResponse)) {
            ModelAndView modelAndView = new ModelAndView("verify");
            modelAndView.addObject("errors", authenticationResponse.getErrors());
            return modelAndView;
        }

        return responseHandler.handleKnownTransitions(authenticationResponse, session);
    }

    /**
     * Handle channel data verification functionality.
     *
     * @param channelName   the channel name
     * @param channelValue  the value for channel
     * @param session the session
     * @return the view associated with authentication response.
     */
    @PostMapping("/verify-channel-data")
    public ModelAndView verifyChannelData(final @RequestParam("channelName") String channelName,
                                          final @RequestParam("channelValue") String channelValue,
                                          final HttpSession session) {
        logger.info(":: Verify Channel Name, Value :: {}, {}", channelName, channelValue);

        ProceedContext proceedContext = Util.getProceedContextFromSession(session);

        VerifyChannelDataOptions verifyChannelDataOptions = new VerifyChannelDataOptions(channelName, channelValue);

        AuthenticationResponse authenticationResponse =
                idxAuthenticationWrapper.verifyAuthenticator(proceedContext, verifyChannelDataOptions);

        if (responseHandler.needsToShowErrors(authenticationResponse)) {
            ModelAndView modelAndView = new ModelAndView("verify");
            modelAndView.addObject("errors", authenticationResponse.getErrors());
            return modelAndView;
        }

        return responseHandler.handleKnownTransitions(authenticationResponse, session);
    }

    /**
     * Handle Okta verify functionality.
     *
     * @param session the session
     * @return the view associated with authentication response.
     */
    @GetMapping("/poll")
    public ModelAndView poll(final HttpSession session) {
        AuthenticationResponse authenticationResponse =
                idxAuthenticationWrapper.poll(Util.getProceedContextFromSession(session));

        if (responseHandler.needsToShowErrors(authenticationResponse)) {
            ModelAndView modelAndView = new ModelAndView("error");
            modelAndView.addObject("errors", authenticationResponse.getErrors());
            return modelAndView;
        }

        return responseHandler.handleKnownTransitions(authenticationResponse, session);
    }

    /**
     * Handle webauthn authenticator verification functionality.
     *
     * @param webauthnRequest
     * @param session the session
     * @return the view associated with authentication response.
     */
    @PostMapping("/verify-webauthn")
    public ModelAndView verifyWebAuthn(final @RequestBody WebAuthnRequest webauthnRequest,
                                       final HttpSession session) {
        logger.info(":: Verify Webauthn ::");

        ProceedContext proceedContext = Util.getProceedContextFromSession(session);

        AuthenticationResponse authenticationResponse = idxAuthenticationWrapper.verifyWebAuthn(
                        proceedContext, webauthnRequest);

        if (responseHandler.needsToShowErrors(authenticationResponse)) {
            ModelAndView modelAndView = new ModelAndView("verify-webauthn");
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
     * @param userProfileAttributes string array for user profile attributes from register form
     * @param session the session
     * @return the enroll authenticators view.
     */
    @PostMapping("/register")
    public ModelAndView register(final @RequestParam(value = "userProfileAttribute[]") String[] userProfileAttributes,
                                 final HttpSession session) {
        logger.info(":: Register ::");

        AuthenticationResponse beginResponse = idxAuthenticationWrapper.begin();
        if (responseHandler.needsToShowErrors(beginResponse)) {
            ModelAndView modelAndView = new ModelAndView("register");
            modelAndView.addObject("errors", beginResponse.getErrors());
            return modelAndView;
        }
        ProceedContext beginProceedContext = beginResponse.getProceedContext();

        AuthenticationResponse newUserRegistrationResponse = idxAuthenticationWrapper.fetchSignUpFormValues(beginProceedContext);
        if (responseHandler.needsToShowErrors(newUserRegistrationResponse)) {
            ModelAndView modelAndView = new ModelAndView("register");
            modelAndView.addObject("errors", newUserRegistrationResponse.getErrors());
            return modelAndView;
        }

        if (responseHandler.needsToShowErrors(newUserRegistrationResponse)) {
            ModelAndView mav = new ModelAndView("register");
            mav.addObject("errors", newUserRegistrationResponse.getErrors());
            return mav;
        }

        UserProfile userProfile = new UserProfile();
//        FormValue userProfileFormValue = null;

//        for (FormValue formValue: newUserRegistrationResponse.getFormValues()) {
//            if (formValue.getName().contentEquals("userProfile")) {
//                userProfileFormValue = formValue;
//            }
//        }

        Optional<FormValue> userProfileFormValue = newUserRegistrationResponse.getFormValues()
                    .stream()
                    .filter(x -> x.getName().equals("userProfile"))
                    .findFirst();

        if (!userProfileFormValue.isPresent()) {
            ModelAndView modelAndView = new ModelAndView("register");
            modelAndView.addObject("errors", "Unknown error occurred!");
            return modelAndView;
        }

        int i = 0;
        for (FormValue value: userProfileFormValue.get().form().getValue()) {
            //Build the user profile
            userProfile.addAttribute(value.getName(), userProfileAttributes[i]);
            i++;
        }

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
     * Handle webauthn authenticator enrollment functionality.
     *
     * @param webauthnRequest body
     * @param session the session
     * @return the view associated with authentication response.
     */
    @PostMapping(value = "/enroll-webauthn")
    public ModelAndView enrollWebauthn(final @RequestBody WebAuthnRequest webauthnRequest,
                                       final HttpSession session) {
        logger.info(":: Enroll Webauthn Authenticator ::");

        ProceedContext proceedContext = Util.getProceedContextFromSession(session);

        AuthenticationResponse authenticationResponse = idxAuthenticationWrapper.verifyWebAuthn(
                proceedContext, webauthnRequest);

        return responseHandler.handleKnownTransitions(authenticationResponse, session);
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
