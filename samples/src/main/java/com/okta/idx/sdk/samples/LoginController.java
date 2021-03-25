package com.okta.idx.sdk.samples;

import com.okta.commons.lang.Assert;
import com.okta.idx.sdk.api.client.Clients;
import com.okta.idx.sdk.api.client.IDXClient;
import com.okta.idx.sdk.api.exception.ProcessingException;
import com.okta.idx.sdk.api.model.IDXClientContext;
import com.okta.idx.sdk.api.response.AuthenticationResponse;
import com.okta.idx.sdk.api.wrapper.AuthenticationHelperUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpSession;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

@RestController
public class LoginController {

    private final Logger logger = LoggerFactory.getLogger(LoginController.class);

    private static final IDXClient client = Clients.builder().build();

    @GetMapping("/samples/login")
    public ModelAndView login() {
        logger.info("==== LOGIN ====");
        return new ModelAndView("login");
    }

    @PostMapping("/samples/login")
    public ModelAndView postLogin(@RequestParam("username") String username,
                                  @RequestParam("password") String password,
                                  HttpSession httpSession) {
        logger.info("==== LOGIN POST ====");

        AuthenticationResponse authenticationResponse = new AuthenticationResponse();

        ModelAndView mav = new ModelAndView("result");

        IDXClientContext clientContext;

        String interactionHandle;

        try {
            clientContext = client.interact();
            interactionHandle = clientContext.getInteractionHandle();
            Assert.hasText(clientContext.getInteractionHandle(), "Missing interaction handle");
        } catch (ProcessingException e) {
            logger.error("Exception occurred while trying to invoke interact API:", e);
            List<String> errors = new LinkedList<>();
            Arrays.stream(e.getErrorResponse().getMessages().getValue()).forEach(msg -> errors.add(msg.getMessage()));
            authenticationResponse.setErrors(errors);
            return mav;
        } catch (IllegalArgumentException e) {
            authenticationResponse.addError(e.getMessage());
            return mav;
        }

        authenticationResponse = AuthenticationHelperUtils.authenticate(client, clientContext, username, password);

        logger.info("Stored interaction handle {} in http session", interactionHandle);
        httpSession.setAttribute("interactionHandle", interactionHandle);
        mav.addObject("authenticationResponse", authenticationResponse);
        return mav;
    }

    @GetMapping("/samples/logout")
    public String postLogout(HttpSession httpSession) {
        logger.info("==== LOGOUT POST ====");

        logger.info("Retrieved interaction handle {} from http session", httpSession.getAttribute("interactionHandle"));
        return "/";
    }
}