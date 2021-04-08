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

    @GetMapping("/")
    public String home() {
        return "redirect:/custom-login";
    }

    @GetMapping(value = "/custom-login")
    public ModelAndView getLogin() {
        return new ModelAndView("login");
    }

    @GetMapping("/forgot-password")
    public ModelAndView getForgotPassword() {
        return new ModelAndView("forgotpassword");
    }


    @GetMapping("/register")
    public ModelAndView getRegister() {
        return new ModelAndView("register");
    }

    @GetMapping("/enroll-authenticators")
    public String getEnrollAuthenticators(Model model) {
        model.addAttribute("authenticatorUIOption", new AuthenticatorUIOption());
        return "enroll-authenticators";
    }

    @GetMapping("/verify-email-authenticator-enrollment")
    public ModelAndView getVerifyEmailAuthenticatorEnrollment() {
        return new ModelAndView("verify-email-authenticator-enrollment");
    }

    @GetMapping("/password-authenticator-enrollment")
    public ModelAndView getPasswordAuthenticatorEnrollment() {
        return new ModelAndView("password-authenticator-enrollment");
    }
}