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
import com.okta.idx.sdk.api.wrapper.AuthenticationWrapper;
import com.okta.spring.example.helpers.HomeHelper;

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
     * idx client instance.
     */
    @Autowired
    private IDXClient client;

    /**
     * home helper instance.
     */
    @Autowired
    private HomeHelper homeHelper;

    /**
     * Handle login with the supplied username and password.
     *
     * @param username the username
     * @param password the password
     * @param session the session
     * @return the home page view (if login is successful), else the login page with errors.
     */
    @PostMapping("/custom-login")
    public ModelAndView handleLogin(final @RequestParam("username") String username,
                                    final @RequestParam("password") String password,
                                    final HttpSession session) {
        // trigger authentication
        AuthenticationResponse authenticationResponse =
                AuthenticationWrapper.authenticate(client, new AuthenticationOptions(username, password));

        // populate login view with errors
        if (authenticationResponse.getAuthenticationStatus() != AuthenticationStatus.SUCCESS) {
            ModelAndView mav = new ModelAndView("login");
            mav.addObject("errors", authenticationResponse.getErrors());
            return mav;
        }

        return homeHelper.proceedToHome(authenticationResponse.getTokenResponse(), session);
    }

    /**
     * Handle forgot password (password recovery) functionality.
     *
     * @param username the username
     * @param authenticatorType the authenticator type
     * @param session the session
     * @return the verify view (if password recovery operation is successful),
     * else the forgot password page with errors.
     */
    @PostMapping("/forgot-password")
    public ModelAndView handleForgotPassword(final @RequestParam("username") String username,
                                             final @RequestParam("authenticatorType") String authenticatorType,
                                             final HttpSession session) {
        logger.info(":: Forgot Password ::");

        AuthenticatorType authType = AuthenticatorType.get(authenticatorType);

        if (authType == null) {
            ModelAndView mav = new ModelAndView("forgot-password");
            mav.addObject("result",
                    "unknown authenticator type - " + authenticatorType);
            return mav;
        }

        AuthenticationResponse authenticationResponse =
                AuthenticationWrapper.recoverPassword(client,
                        new RecoverPasswordOptions(username, authType));

        if (authenticationResponse.getAuthenticationStatus() == null) {
            ModelAndView mav = new ModelAndView("forgot-password");
            mav.addObject("result", authenticationResponse.getErrors());
            return mav;
        }

        if (authenticationResponse.getAuthenticationStatus()
                .equals(AuthenticationStatus.AWAITING_AUTHENTICATOR_VERIFICATION)) {
            session.setAttribute("idxClientContext", authenticationResponse.getIdxClientContext());
            return new ModelAndView("verify");
        }

        return new ModelAndView("login"); //TODO revisit this
    }

    /**
     * Handle email verification functionality.
     *
     * @param code the email verification code
     * @param session the session
     * @return the change password view (if awaiting password reset), else the login page.
     */
    @PostMapping("/verify")
    public ModelAndView handleEmailVerify(final @RequestParam("code") String code,
                                          final HttpSession session) {
        logger.info(":: Verify Code :: {}", code);

        IDXClientContext idxClientContext = (IDXClientContext) session.getAttribute("idxClientContext");

        VerifyAuthenticatorOptions verifyAuthenticatorOptions = new VerifyAuthenticatorOptions();
        verifyAuthenticatorOptions.setCode(code);

        AuthenticationResponse authenticationResponse =
                AuthenticationWrapper.verifyAuthenticator(client, idxClientContext, verifyAuthenticatorOptions);

        if (authenticationResponse.getErrors().size() > 0) {
            ModelAndView mav = new ModelAndView("login");
            mav.addObject("errors", authenticationResponse.getErrors());
            return mav;
        }

        if (authenticationResponse.getAuthenticationStatus() == AuthenticationStatus.AWAITING_PASSWORD_RESET) {
            return new ModelAndView("change-password");
        }

        ModelAndView mav = new ModelAndView("login");
        mav.addObject("messages", authenticationResponse.getAuthenticationStatus().toString());
        return mav;
    }

    /**
     * Handle change password functionality.
     *
     * @param newPassword the new password
     * @param confirmNewPassword the confirmation of the new password
     * @param session the session
     * @return the login view
     */
    @PostMapping("/change-password")
    public ModelAndView handleChangePassword(final @RequestParam("new-password") String newPassword,
                                             final @RequestParam("confirm-new-password") String confirmNewPassword,
                                             final HttpSession session) {
        logger.info(":: Change Password ::");

        if (!newPassword.equals(confirmNewPassword)) {
            ModelAndView mav = new ModelAndView("change-password");
            mav.addObject("errors", "Passwords do not match");
            return mav;
        }

        IDXClientContext idxClientContext = (IDXClientContext) session.getAttribute("idxClientContext");

        ChangePasswordOptions changePasswordOptions = new ChangePasswordOptions();
        changePasswordOptions.setNewPassword(newPassword);

        AuthenticationResponse authenticationResponse =
                AuthenticationWrapper.changePassword(client, idxClientContext, changePasswordOptions);

        if (authenticationResponse.getErrors().size() > 0) {
            ModelAndView mav = new ModelAndView("change-password");
            mav.addObject("errors", authenticationResponse.getErrors());
            return mav;
        }

        ModelAndView mav = new ModelAndView("login");
        mav.addObject("info", authenticationResponse.getAuthenticationStatus().toString());
        return mav;
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
    public ModelAndView handleRegister(final @RequestParam("lastname") String lastname,
                                       final @RequestParam("firstname") String firstname,
                                       final @RequestParam("email") String email,
                                       final HttpSession session) {
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

        List<AuthenticatorUIOption> authenticatorUIOptionList =
                AuthenticationWrapper.populateAuthenticatorUIOptions(client, idxClientContext);

        mav.addObject("authenticatorUIOptionList", authenticatorUIOptionList);

        session.setAttribute("idxClientContext", authenticationResponse.getIdxClientContext());
        return mav;
    }

    /**
     * Handle authenticator enrollment functionality.
     *
     * @param authenticatorType the authenticator type
     * @param session the session
     * @return the email or password authenticator enrollment view, else the enroll authenticators page with errors.
     */
    @PostMapping(value = "/enroll-authenticator")
    public ModelAndView handleEnrollAuthenticator(final @RequestParam("authenticator-type") String authenticatorType,
                                                  final HttpSession session) {
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

    /**
     * Handle email authenticator verification functionality.
     *
     * @param code the email verification code
     * @param session the session
     * @return the login page view (if login operation is successful), else the enroll-authenticators page.
     */
    @PostMapping(value = "/verify-email-authenticator-enrollment")
    public ModelAndView handleVerifyEmailAuthenticator(final @RequestParam("code") String code,
                                                       final HttpSession session) {
        logger.info(":: Verify Email Authenticator :: {}", code);

        IDXClientContext idxClientContext = (IDXClientContext) session.getAttribute("idxClientContext");

        AuthenticationResponse authenticationResponse =
                AuthenticationWrapper.verifyEmailAuthenticator(client, idxClientContext, code);

        if (authenticationResponse.getTokenResponse() != null) {
            return homeHelper.proceedToHome(authenticationResponse.getTokenResponse(), session);
        }

        idxClientContext = authenticationResponse.getIdxClientContext();

        if (AuthenticationWrapper.isSkipAuthenticatorPresent(client, idxClientContext)) {
            AuthenticationResponse response =
                    AuthenticationWrapper.skipAuthenticatorEnrollment(client, idxClientContext);
            if (response.getTokenResponse() != null) {
                return homeHelper.proceedToHome(response.getTokenResponse(), session);
            }
        }

        ModelAndView mav = new ModelAndView("enroll-authenticators");

        List<AuthenticatorUIOption> authenticatorUIOptionList =
                AuthenticationWrapper.populateAuthenticatorUIOptions(client, idxClientContext);

        mav.addObject("authenticatorUIOptionList", authenticatorUIOptionList);
        session.setAttribute("idxClientContext", idxClientContext);
        return mav;
    }

    /**
     * Handle password authenticator enrollment functionality.
     *
     * @param newPassword the new password
     * @param confirmNewPassword the confirmation for new password
     * @param session the session
     * @return the login page view (if login operation is successful), else the enroll-authenticators page.
     */
    @PostMapping(value = "/password-authenticator-enrollment")
    public ModelAndView handleEnrollPasswordAuthenticator(final @RequestParam("new-password") String newPassword,
                                                          final @RequestParam("confirm-new-password") String confirmNewPassword,
                                                          final HttpSession session) {
        logger.info(":: Enroll Password Authenticator ::");

        if (!newPassword.equals(confirmNewPassword)) {
            ModelAndView mav = new ModelAndView("password-authenticator-enrollment");
            mav.addObject("result", "Passwords do not match");
            return mav;
        }

        IDXClientContext idxClientContext = (IDXClientContext) session.getAttribute("idxClientContext");

        AuthenticationResponse authenticationResponse =
                AuthenticationWrapper.verifyPasswordAuthenticator(client, idxClientContext, confirmNewPassword);

        if (authenticationResponse.getTokenResponse() != null) {
            return homeHelper.proceedToHome(authenticationResponse.getTokenResponse(), session);
        }

        idxClientContext = authenticationResponse.getIdxClientContext();

        if (AuthenticationWrapper.isSkipAuthenticatorPresent(client, idxClientContext)) {
            AuthenticationResponse response =
                    AuthenticationWrapper.skipAuthenticatorEnrollment(client, idxClientContext);

            if (response.getTokenResponse() != null) {
                return homeHelper.proceedToHome(response.getTokenResponse(), session);
            }
        }

        ModelAndView mav = new ModelAndView("enroll-authenticators");

        List<AuthenticatorUIOption> authenticatorUIOptionList =
                AuthenticationWrapper.populateAuthenticatorUIOptions(client, idxClientContext);

        mav.addObject("authenticatorUIOptionList", authenticatorUIOptionList);
        session.setAttribute("idxClientContext", idxClientContext);
        return mav;
    }
}
