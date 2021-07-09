/*
 * Copyright (c) 2020-Present, Okta, Inc.
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

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpSession;

@Controller
public class HomeController {

    @GetMapping("/")
    public String home(
            @RequestParam(name = "error", required = false) String error,
            @RequestParam(name = "interaction_code", required = false) String interactionCode,
            @RequestParam(name = "state", required = false) String state,
            HttpSession session) {

        //MFA disabled
        if (interactionCode != null && state != null) {
            String oauthAuthUri =
                    String.format("/oauth2/authorization/okta?interaction_code=%s&state=%s", interactionCode, state);
            return "redirect:" + oauthAuthUri;
        }
        //MFA enabled
        if (state != null && error != null && error.equals("interaction_required")) {
            String oauthAuthUri =
                    String.format("/oauth2/authorization/okta?error=%s&state=%s", error, state);
            return "redirect:" + oauthAuthUri;
        }
        //cleanup the context in case of unsuccessful login
        if(error != null && error.equals("access_denied")) {
            session.setAttribute("idxClientContext", null);
        }
        return "home";
    }
}
