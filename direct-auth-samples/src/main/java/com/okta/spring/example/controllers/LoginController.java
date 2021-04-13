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

import com.okta.idx.sdk.api.client.IDXClient;
import com.okta.idx.sdk.api.model.AuthenticationOptions;
import com.okta.idx.sdk.api.model.AuthenticationStatus;
import com.okta.idx.sdk.api.model.AuthenticatorType;
import com.okta.idx.sdk.api.model.AuthenticatorUIOption;
import com.okta.idx.sdk.api.model.ChangePasswordOptions;
import com.okta.idx.sdk.api.model.IDXClientContext;
import com.okta.idx.sdk.api.model.RecoverPasswordOptions;
import com.okta.idx.sdk.api.model.UserProfile;
import com.okta.idx.sdk.api.model.VerifyAuthenticatorOptions;
import com.okta.idx.sdk.api.response.AuthenticationResponse;
import com.okta.idx.sdk.api.response.NewUserRegistrationResponse;
import com.okta.idx.sdk.api.response.TokenResponse;
import com.okta.idx.sdk.api.wrapper.AuthenticationWrapper;
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

    private final Logger logger = LoggerFactory.getLogger(LoginController.class);

    @Autowired
    private IDXClient client;

    @PostMapping("/custom-login")
    public ModelAndView handleLogin(@RequestParam("username") String username,
                                    @RequestParam("password") String password,
                                    HttpSession session) {

        TokenResponse tokenResponse =
                (TokenResponse) session.getAttribute("tokenResponse");

        // render existing token response if a successful one is already present in session
        if (tokenResponse != null) {
            ModelAndView mav = new ModelAndView("home");
            AuthenticationResponse authenticationResponse = new AuthenticationResponse();
            authenticationResponse.setAuthenticationStatus(AuthenticationStatus.SUCCESS);
            authenticationResponse.setTokenResponse(tokenResponse);
            mav.addObject("authenticationResponse", authenticationResponse);
            return mav;
        }

        // trigger authentication
        AuthenticationResponse authenticationResponse =
                AuthenticationWrapper.authenticate(client, new AuthenticationOptions(username, password));

        // populate login view with errors
        if (authenticationResponse.getAuthenticationStatus() != AuthenticationStatus.SUCCESS) {
            ModelAndView mav = new ModelAndView("login");
            mav.addObject("errors", authenticationResponse.getErrors());
            return mav;
        }

        // success
        ModelAndView mav = new ModelAndView("home");
        mav.addObject("authenticationResponse", authenticationResponse);

        // store attributes in session
        session.setAttribute("user", username);
        session.setAttribute("tokenResponse", authenticationResponse.getTokenResponse());
        return mav;
    }

    @PostMapping("/forgot-password")
    public ModelAndView handleForgotPassword(@RequestParam("username") String username,
                                             @RequestParam("authenticatorType") String authenticatorType,
                                             HttpSession httpSession) {
        logger.info(":: Forgot Password ::");

        //TODO
        AuthenticationResponse authenticationResponse =
                AuthenticationWrapper.recoverPassword(client, new RecoverPasswordOptions(username, AuthenticatorType.EMAIL));

        if (authenticationResponse.getAuthenticationStatus() == null) {
            ModelAndView mav = new ModelAndView("forgot-password");
            mav.addObject("result", authenticationResponse.getErrors());
            return mav;
        }

        if (authenticationResponse.getAuthenticationStatus().equals(AuthenticationStatus.AWAITING_AUTHENTICATOR_VERIFICATION)) {
            httpSession.setAttribute("idxClientContext", authenticationResponse.getIdxClientContext());
            return new ModelAndView("verify");
        }

        return new ModelAndView("login"); //TODO revisit this
    }

    @PostMapping("/verify")
    public ModelAndView handleEmailVerify(@RequestParam("code") String code,
                                          HttpSession httpSession) {
        logger.info(":: Verify Code :: {}", code);

        IDXClientContext idxClientContext = (IDXClientContext) httpSession.getAttribute("idxClientContext");

        VerifyAuthenticatorOptions verifyAuthenticatorOptions = new VerifyAuthenticatorOptions();
        verifyAuthenticatorOptions.setCode(code);

        AuthenticationResponse authenticationResponse =
                AuthenticationWrapper.verifyAuthenticator(client, idxClientContext, verifyAuthenticatorOptions);

        if (authenticationResponse.getAuthenticationStatus() == AuthenticationStatus.AWAITING_PASSWORD_RESET) {
            return new ModelAndView("change-password");
        }

        ModelAndView mav = new ModelAndView("login");
        mav.addObject("messages", authenticationResponse.getAuthenticationStatus().toString());
        return mav;
    }

    @PostMapping("/change-password")
    public ModelAndView handleChangePassword(@RequestParam("new-password") String newPassword,
                                             @RequestParam("confirm-new-password") String confirmNewPassword,
                                             HttpSession httpSession) {
        logger.info(":: Change Password ::");

        if (!newPassword.equals(confirmNewPassword)) {
            ModelAndView mav = new ModelAndView("change-password");
            mav.addObject("errors", "Passwords do not match");
            return mav;
        }

        ModelAndView mav = new ModelAndView("login");

        IDXClientContext idxClientContext = (IDXClientContext) httpSession.getAttribute("idxClientContext");

        ChangePasswordOptions changePasswordOptions = new ChangePasswordOptions();
        changePasswordOptions.setNewPassword(newPassword);

        AuthenticationResponse authenticationResponse =
                AuthenticationWrapper.changePassword(client, idxClientContext, changePasswordOptions);

        mav.addObject("info", authenticationResponse.getAuthenticationStatus().toString());
        return mav;
    }

    @PostMapping("/register")
    public ModelAndView handleRegister(@RequestParam("lastname") String lastname,
                                       @RequestParam("firstname") String firstname,
                                       @RequestParam("email") String email,
                                       HttpSession session) {
        logger.info(":: Register ::");

        ModelAndView mav = new ModelAndView("enroll-authenticators");

        NewUserRegistrationResponse newUserRegistrationResponse = AuthenticationWrapper.fetchSignUpFormValues(client);

        UserProfile userProfile = new UserProfile();
        userProfile.addAttribute("lastName", lastname);
        userProfile.addAttribute("firstName", firstname);
        userProfile.addAttribute("email", email);

        IDXClientContext idxClientContext = newUserRegistrationResponse.getIdxClientContext();

        AuthenticationResponse authenticationResponse =
                AuthenticationWrapper.register(client, idxClientContext, userProfile);

        List<AuthenticatorUIOption> authenticatorUIOptionList = AuthenticationWrapper.populateAuthenticatorUIOptions(client, idxClientContext);

        mav.addObject("authenticatorUIOptionList", authenticatorUIOptionList);

        session.setAttribute("idxClientContext", authenticationResponse.getIdxClientContext());
        return mav;
    }

    @PostMapping(value = "/enroll-authenticator")
    public ModelAndView handleEnrollAuthenticator(@RequestParam("authenticator-type") String authenticatorType,
                                                  HttpSession session) {
        logger.info(":: Enroll Authenticator ::");

        IDXClientContext idxClientContext = (IDXClientContext) session.getAttribute("idxClientContext");

        AuthenticationResponse authenticationResponse =
                AuthenticationWrapper.enrollAuthenticator(client, idxClientContext, authenticatorType);

        session.setAttribute("idxClientContext", authenticationResponse.getIdxClientContext());

        if (authenticationResponse.getErrors().size() > 0) {
            ModelAndView mav = new ModelAndView("enroll-authenticators");
            mav.addObject("messages", authenticationResponse.getAuthenticationStatus().toString());
            return mav;
        }


        if (authenticatorType.equals(AuthenticatorType.EMAIL.toString())) {
            return new ModelAndView("verify-email-authenticator-enrollment");
        } else if (authenticatorType.equals(AuthenticatorType.PASSWORD.toString())) {
            return new ModelAndView("password-authenticator-enrollment");
        } else {
            logger.error("Unsupported authenticator {}", authenticatorType);
            return new ModelAndView("enroll-authenticators");
        }
    }

    @PostMapping(value = "/verify-email-authenticator-enrollment")
    public ModelAndView handleVerifyEmailAuthenticator(@RequestParam("code") String code,
                                                       HttpSession session) {
        logger.info(":: Verify Email Authenticator :: {}", code);

        IDXClientContext idxClientContext = (IDXClientContext) session.getAttribute("idxClientContext");

        AuthenticationResponse authenticationResponse =
                AuthenticationWrapper.verifyEmailAuthenticator(client, idxClientContext, code);

        idxClientContext = authenticationResponse.getIdxClientContext();

        if (AuthenticationWrapper.isTerminalSuccess(client, idxClientContext)) {
            ModelAndView mav = new ModelAndView("login");
            mav.addObject("info", "Registration successful");
            return mav;
        }

        if (AuthenticationWrapper.isSkipAuthenticatorPresent(client, idxClientContext)) {
            AuthenticationResponse response = AuthenticationWrapper.skipAuthenticatorEnrollment(client, idxClientContext);
            idxClientContext = response.getIdxClientContext();

            if (AuthenticationWrapper.isTerminalSuccess(client, idxClientContext)) {
                session.setAttribute("idxClientContext", idxClientContext);
                ModelAndView mav = new ModelAndView("login");
                mav.addObject("info", "Registration successful");
                return mav;
            }
        }

        ModelAndView mav = new ModelAndView("enroll-authenticators");

        List<AuthenticatorUIOption> authenticatorUIOptionList = AuthenticationWrapper.populateAuthenticatorUIOptions(client, idxClientContext);

        mav.addObject("authenticatorUIOptionList", authenticatorUIOptionList);
        session.setAttribute("idxClientContext", idxClientContext);
        return mav;
    }

    @PostMapping(value = "/password-authenticator-enrollment")
    public ModelAndView handleEnrollPasswordAuthenticator(@RequestParam("new-password") String newPassword,
                                                          @RequestParam("confirm-new-password") String confirmNewPassword,
                                                          HttpSession session) {
        logger.info(":: Enroll Password Authenticator ::");

        if (!newPassword.equals(confirmNewPassword)) {
            ModelAndView mav = new ModelAndView("password-authenticator-enrollment");
            mav.addObject("result", "Passwords do not match");
            return mav;
        }

        IDXClientContext idxClientContext = (IDXClientContext) session.getAttribute("idxClientContext");

        AuthenticationResponse authenticationResponse =
                AuthenticationWrapper.verifyPasswordAuthenticator(client, idxClientContext, confirmNewPassword);

        idxClientContext = authenticationResponse.getIdxClientContext();

        if (AuthenticationWrapper.isTerminalSuccess(client, idxClientContext)) {
            ModelAndView mav = new ModelAndView("login");
            mav.addObject("info", "Registration successful");
            return mav;
        }

        if (AuthenticationWrapper.isSkipAuthenticatorPresent(client, idxClientContext)) {
            AuthenticationResponse response = AuthenticationWrapper.skipAuthenticatorEnrollment(client, idxClientContext);

            if (AuthenticationWrapper.isTerminalSuccess(client, response.getIdxClientContext())) {
                session.setAttribute("idxClientContext", idxClientContext);
                ModelAndView mav = new ModelAndView("login");
                mav.addObject("info", "Registration successful");
                return mav;
            }
        }

        ModelAndView mav = new ModelAndView("enroll-authenticators");

        List<AuthenticatorUIOption> authenticatorUIOptionList = AuthenticationWrapper.populateAuthenticatorUIOptions(client, idxClientContext);

        mav.addObject("authenticatorUIOptionList", authenticatorUIOptionList);
        session.setAttribute("idxClientContext", idxClientContext);
        return mav;
    }
}