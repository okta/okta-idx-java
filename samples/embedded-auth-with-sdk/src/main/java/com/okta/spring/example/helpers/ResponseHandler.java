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

import com.okta.idx.sdk.api.client.Authenticator;
import com.okta.idx.sdk.api.client.IDXAuthenticationWrapper;
import com.okta.idx.sdk.api.model.AuthenticatorEnrollment;
import com.okta.idx.sdk.api.model.AuthenticatorEnrollments;
import com.okta.idx.sdk.api.response.AuthenticationResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.ModelAndView;

import jakarta.servlet.http.HttpSession;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static com.okta.idx.sdk.api.model.AuthenticationStatus.SKIP_COMPLETE;

@Component
public final class ResponseHandler {

    /**
     * response handler.
     */
    @Autowired
    private HomeHelper homeHelper;

    /**
     * idx authentication wrapper instance.
     */
    @Autowired
    private IDXAuthenticationWrapper authenticationWrapper;

    /**
     * Check if response contains presentable errors.
     *
     * @param response the response
     * @return true if the caller should show errors; false otherwise
     */
    public boolean needsToShowErrors(AuthenticationResponse response) {
        return !response.getErrors().isEmpty();
    }

    /**
     * Return terminal views based on the authentication status in response.
     * @param response the response
     * @param session the session
     * @return the view associated with the response authentication status or null.
     */
    public ModelAndView handleTerminalTransitions(AuthenticationResponse response, HttpSession session) {
        Util.updateSession(session, response.getProceedContext());
        if (response.getTokenResponse() != null) {
            return homeHelper.proceedToHome(response.getTokenResponse(), session);
        }

        if (response.getAuthenticators() == null && response.getErrors().size() > 0) {
            ModelAndView modelAndView = new ModelAndView("error");
            modelAndView.addObject("errors", response.getErrors());
            return modelAndView;
        }

        if (response.getAuthenticationStatus() == SKIP_COMPLETE) {
            ModelAndView modelAndView = homeHelper.proceedToHome(response.getTokenResponse(), session);
            modelAndView.addObject("info", response.getErrors());
            return modelAndView;
        }
        return null;
    }

    /**
     * Return view based on the authentication status in response.
     *
     * @param response the response
     * @param session the session
     * @return the view with the status associated with the response.
     */
    public ModelAndView handleKnownTransitions(AuthenticationResponse response, HttpSession session) {
        ModelAndView terminalModelAndView = handleTerminalTransitions(response, session);
        if (terminalModelAndView != null) {
            return terminalModelAndView;
        }

        switch (response.getAuthenticationStatus()) {
            case AWAITING_PASSWORD_RESET:
                return registerPasswordForm("Reset Password");
            case PASSWORD_EXPIRED:
                return registerPasswordForm("Password Expired");
            case AWAITING_AUTHENTICATOR_SELECTION:
            case AWAITING_AUTHENTICATOR_VERIFICATION_DATA:
                return selectAuthenticatorForm(response, "Select Authenticator", session);
            case AWAITING_AUTHENTICATOR_ENROLLMENT:
            case AWAITING_AUTHENTICATOR_VERIFICATION:
                // If webauthn, webAuthParams is present, otherwise
                // currentAuthenticatorEnrollment
                if (null != response.getWebAuthnParams().getCurrentAuthenticator()) {
                    if (response.getWebAuthnParams().getCurrentAuthenticator().getValue().getDisplayName()
                            .equals("Security Key or Biometric")) {

                        AuthenticatorEnrollments authenticatorEnrollments = response.getAuthenticatorEnrollments();
                        Optional<AuthenticatorEnrollment> authenticatorOptional = authenticatorEnrollments.stream()
                                .filter(auth -> auth.getKey().equals("webauthn")).findFirst();
                        String credentialID = authenticatorOptional.get().getCredentialId();

                        response.getWebAuthnParams().setWebauthnCredentialId(credentialID);
                        return verifyWebauthn(response);
                    }
                } else {
                    return verifyForm();
                }
            case AWAITING_AUTHENTICATOR_ENROLLMENT_SELECTION:
                return selectAuthenticatorForm(response, "Enroll Authenticator", session);
            case AWAITING_POLL_ENROLLMENT:
                return setupOktaVerifyForm(session);
            default:
                return unsupportedPolicy();
        }
    }

    /**
     * Return the view for select authenticator form.
     * @param response the response
     * @param title the view title
     * @param session the session
     * @return the view associated with the response authentication status.
     */
    public ModelAndView selectAuthenticatorForm(AuthenticationResponse response, String title, HttpSession session) {

        boolean canSkip = authenticationWrapper.isSkipAuthenticatorPresent(response.getProceedContext());
        ModelAndView modelAndView = new ModelAndView("select-authenticator");
        modelAndView.addObject("canSkip", canSkip);
        List<String> factorMethods = new ArrayList<>();
        for (Authenticator authenticator : response.getAuthenticators()) {
            for (Authenticator.Factor factor : authenticator.getFactors()) {
                factorMethods.add(factor.getMethod());
            }
        }
        session.setAttribute("authenticators", response.getAuthenticators());
        modelAndView.addObject("factorList", factorMethods);
        modelAndView.addObject("authenticators", response.getAuthenticators());
        modelAndView.addObject("title", title);
        return modelAndView;
    }

    /**
     * Return the view for Okta Verify challenge.
     * @param response the response
     * @return the view for the register verify form.
     */
    public ModelAndView oktaVerifyChallenge(AuthenticationResponse response) {
        ModelAndView modelAndView = new ModelAndView("okta-verify-challenge");
        if (response.getContextualData() != null) {
            modelAndView.addObject("correctAnswer", response.getContextualData().getCorrectAnswer());
        }
        modelAndView.addObject("pollTimeout", response.getProceedContext().getRefresh());
        return modelAndView;
    }

    /**
     * Return the view for register verify form.
     * @param factor the factor
     * @param authenticationResponse authentication response
     * @return the view for the register verify form.
     */
    public ModelAndView registerVerifyForm(Authenticator.Factor factor, AuthenticationResponse authenticationResponse) {
        switch (factor.getMethod()) {
            case "email":
                return verifyForm();
            case "password":
                return registerPasswordForm("Setup Password");
            case "voice":
            case "sms":
                ModelAndView modelAndView = new ModelAndView("register-phone");
                modelAndView.addObject("mode", factor.getMethod());
                return modelAndView;
            default:
                return unsupportedPolicy();
        }
    }

    /**
     * Return the view for verify form.
     * @param authenticator the authenticator
     * @param authenticationResponse authentication response
     * @return the view for the register verify form.
     */
    public ModelAndView registerVerifyForm(Authenticator authenticator,
                                           AuthenticationResponse authenticationResponse) {
        switch (authenticator.getLabel()) {
            case "Email":
                return verifyForm();
            case "Password":
                return registerPasswordForm("Setup Password");
            case "Phone":
                return new ModelAndView("register-phone");
            case "Google Authenticator":
                return new ModelAndView("register-google");
            case "Security Question":
                ModelAndView modelAndView = new ModelAndView("register-sec-qn");
                modelAndView.addObject("title", "Security Question");
                modelAndView.addObject("questions", authenticationResponse.getSecurityQuestions());
                return modelAndView;
            case "Security Key or Biometric":
                ModelAndView mav = new ModelAndView("enroll-webauthn-authenticator");
                mav.addObject("title", "Enroll Webauthn Authenticator");
                mav.addObject("currentAuthenticator",
                        authenticationResponse.getWebAuthnParams().getCurrentAuthenticator());
                return mav;
            default:
                return unsupportedPolicy();
        }
    }

    /**
     * Return the view for verify form.
     * @return the view for verifyForm.
     */
    public ModelAndView verifyForm() {
        return new ModelAndView("verify");
    }

    /**
     * Return the view for verify form.
     * @param response the authentication response
     * @return the view for verifyForm.
     */
    public ModelAndView verifyForm(AuthenticationResponse response) {
        ModelAndView modelAndView = new ModelAndView("verify");
        if (response.getCurrentAuthenticatorEnrollment() != null
                && "security_question".equals(response.getCurrentAuthenticatorEnrollment().getValue().getType())) {
            modelAndView.addObject("security_question",
                    response.getCurrentAuthenticatorEnrollment().getValue().getProfile().getQuestion());
            modelAndView.addObject("security_question_key",
                    response.getCurrentAuthenticatorEnrollment().getValue().getProfile().getQuestionKey());
        }
        return modelAndView;
    }

    /**
     * Return the view for okta verify form via channel data.
     * @param factor the factor
     * @param session the session
     * @return the view for okta verify form via channel data.
     */
    public ModelAndView oktaVerifyViaChannelDataForm(Authenticator.Factor factor, HttpSession session) {
        ModelAndView modelAndView = new ModelAndView("setup-okta-verify-via-channel-data");
        modelAndView.addObject("channelName", factor.getChannel());
        switch (factor.getChannel()) {
            case "email":
                modelAndView.addObject("title", "Set up Okta Verify via email link");
                modelAndView.addObject("labelTitle", "Email");
                modelAndView.addObject("buttonTitle", "Send me the setup link");
                modelAndView.addObject("message", "Make sure you can access the email on your mobile device.");
                modelAndView.addObject("channelName", "email");
                session.setAttribute("channelName", "email");
                break;
            case "sms":
                modelAndView.addObject("title", "Set up Okta Verify via SMS");
                modelAndView.addObject("labelTitle", "Phone number");
                modelAndView.addObject("buttonTitle", "Send me the setup link");
                modelAndView.addObject("message", "Make sure you can access the text on your mobile device.");
                modelAndView.addObject("channelName", "phoneNumber");
                session.setAttribute("channelName", "phoneNumber");
                break;
            default:
                break;
        }
        return modelAndView;
    }

    /**
     * Return the view for okta verify form.
     * @param session the session
     * @return the view for okta verify form.
     */
    public ModelAndView setupOktaVerifyForm(HttpSession session) {
        ModelAndView modelAndView = new ModelAndView("setup-okta-verify");
        modelAndView.addObject("channelName", String.valueOf(session.getAttribute("channelName")));
        modelAndView.addObject("pollTimeout", Util.getProceedContextFromSession(session).getRefresh());
        return modelAndView;
    }

    /**
     * Return the view for register password form.
     * @param title the title of form
     * @return the view for password registration form.
     */
    private ModelAndView registerPasswordForm(String title) {
        ModelAndView modelAndView = new ModelAndView("register-password");
        modelAndView.addObject("title", title);
        return modelAndView;
    }

    /**
     * Return the view for verify form.
     * @param enrollResponse the enrollment response
     * @return the view for verifyForm.
     */
    public ModelAndView verifyWebauthn(AuthenticationResponse enrollResponse) {
        String webauthnCredentialId = enrollResponse.getWebAuthnParams().getWebauthnCredentialId();
        ModelAndView modelAndView = new ModelAndView("verify-webauthn-authenticator");
        modelAndView.addObject("title", "Select WebAuthn Authenticator");
        modelAndView.addObject("webauthnCredentialId", webauthnCredentialId);
        modelAndView.addObject("challengeData", enrollResponse.getWebAuthnParams().getCurrentAuthenticator().getValue()
                .getContextualData().getChallengeData());
        return modelAndView;
    }

    /**
     * Return the view for unsupported policy.
     * @return the view for policy errors.
     */
    private ModelAndView unsupportedPolicy() {
        ModelAndView modelAndView = new ModelAndView("error");
        modelAndView.addObject("errors", "Unsupported Policy.");
        return modelAndView;
    }
}
