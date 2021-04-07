package com.okta.spring.example.controllers;

import com.okta.idx.sdk.api.model.AuthenticatorUIOption;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpSession;

@Controller
public class HomeController {

    private final Logger logger = LoggerFactory.getLogger(HomeController.class);

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

    @GetMapping("/signup")
    public ModelAndView getSignup() {
        return new ModelAndView("signup");
    }

    @GetMapping("/register")
    public ModelAndView getRegister() {
        return new ModelAndView("register");
    }

    @GetMapping("/enroll-authenticators")
    public String getEnrollAuthenticators(Model model) {
//        ModelAndView modelAndView = new ModelAndView("enroll-authenticators");
//        modelAndView.addObject("authenticatorUIOption", new AuthenticatorUIOption());
//        return modelAndView;

        logger.info(" :: getEnrollAuthenticators() ::");

        model.addAttribute("authenticatorUIOption", new AuthenticatorUIOption());
        return "enroll-authenticators";
    }

    @GetMapping("/enroll-authenticator")
    public String getEnrollAuthenticator(Model model) {
        logger.info(" :: getEnrollAuthenticator() ::");

        model.addAttribute("authenticatorUIOption", new AuthenticatorUIOption());
        return "enroll-authenticator";
    }

    @GetMapping("/verify-email-authenticator-enrollment")
    public ModelAndView getVerifyEmailAuthenticatorEnrollment() {
        return new ModelAndView("verify-email-authenticator-enrollment");
    }

    @GetMapping("/password-authenticator-enrollment")
    public ModelAndView getPasswordAuthenticatorEnrollment() {
        return new ModelAndView("password-authenticator-enrollment");
    }

    @GetMapping("/logout")
    public String logout(HttpSession session ) {
        session.invalidate();
        return "redirect:/custom-login";
    }
}