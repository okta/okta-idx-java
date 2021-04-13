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

import com.okta.idx.sdk.api.model.AuthenticatorUIOption;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.ModelAndView;

@Controller
public class HomeController {

    /**
     * Display the home page.
     *
     * @return the redirection to login view
     */
    @GetMapping("/")
    public String displayHomePage() {
        return "redirect:/custom-login";
    }

    /**
     * Display the login page.
     *
     * @return the login view
     */
    @GetMapping(value = "/custom-login")
    public ModelAndView displayLoginPage() {
        return new ModelAndView("login");
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
     * Display the enroll authenticators page.
     *
     * @param model the model
     * @return the enroll authenticators view
     */
    @GetMapping("/enroll-authenticators")
    public String displayEnrollAuthenticatorsPage(final Model model) {
        model.addAttribute("authenticatorUIOption", new AuthenticatorUIOption());
        return "enroll-authenticators";
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
