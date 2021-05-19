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

import com.okta.idx.sdk.api.client.Authenticator;
import com.okta.idx.sdk.api.client.IDXAuthenticationWrapper;
import com.okta.idx.sdk.api.response.AuthenticationResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.ModelAndView;

import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpSession;

import static com.okta.idx.sdk.api.model.AuthenticationStatus.*;

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

    public ModelAndView handleTerminalTransitions(AuthenticationResponse response, HttpSession session) {
        Util.updateSession(session, response.getProceedContext());
        if (response.getTokenResponse() != null) {
            return homeHelper.proceedToHome(response.getTokenResponse(), session);
        }
        if (response.getAuthenticationStatus() == SKIP_COMPLETE) {
            ModelAndView modelAndView = homeHelper.proceedToHome(response.getTokenResponse(), session);
            // TODO: Need to test this.
            modelAndView.addObject("info", response.getErrors());
            return modelAndView;
        }
        if (!response.getErrors().isEmpty()) {
            // TODO: Go to the current page, and show the errors.
        }
        return null;
    }

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
                return selectAuthenticatorForm(response, "Select Authenticator", session);
            case AWAITING_AUTHENTICATOR_VERIFICATION:
                return verifyForm();
            case AWAITING_AUTHENTICATOR_ENROLLMENT_SELECTION:
                return selectAuthenticatorForm(response, "Enroll Authenticator", session);
            default:
                return unsupportedPolicy();
        }
    }

    private ModelAndView selectAuthenticatorForm(AuthenticationResponse response, String title, HttpSession session) {
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
        modelAndView.addObject("title", title);
        return modelAndView;
    }

    public ModelAndView registerVerifyForm(Authenticator.Factor factor) {
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

    public ModelAndView verifyForm() {
        return new ModelAndView("verify");
    }

    private ModelAndView registerPasswordForm(String title) {
        ModelAndView modelAndView = new ModelAndView("register-password");
        modelAndView.addObject("title", title);
        return modelAndView;
    }

    private ModelAndView unsupportedPolicy() {
        ModelAndView modelAndView = new ModelAndView("error");
        modelAndView.addObject("errors", "Unsupported Policy.");
        return modelAndView;
    }
}
