package com.okta.spring.example.helpers;

import com.okta.idx.sdk.api.response.TokenResponse;
import com.okta.jwt.AccessTokenVerifier;
import com.okta.jwt.JwtVerificationException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpSession;

@Component
public class HomeHelper {
    /**
     * jwt parser instance.
     */
    @Autowired
    private AccessTokenVerifier accessTokenVerifier;

    /**
     * Go to the home page, setting the session, and creating the view.
     * @param tokenResponse
     * @param session
     * @return the ModelAndView for the home page.
     */
    public ModelAndView proceedToHome(final TokenResponse tokenResponse, final HttpSession session) {
        // success
        ModelAndView mav = new ModelAndView("home");
        mav.addObject("tokenResponse", tokenResponse);
        String user = null;
        try {
            user = (String) accessTokenVerifier.decode(tokenResponse.idToken).getClaims().get("email");
        } catch (JwtVerificationException e) {
            e.printStackTrace();
        }
        mav.addObject("user", user);

        // store token in session
        session.setAttribute("tokenResponse", tokenResponse);

        return mav;
    }
}
