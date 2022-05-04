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

import com.okta.idx.sdk.api.client.ProceedContext;
import com.okta.idx.sdk.api.model.RequestContext;

import javax.servlet.http.HttpSession;
import java.util.UUID;

public final class Util {

    /**
     * removeProceedContextFromSession.
     *
     * @param session the session
     */
    public static void removeProceedContextFromSession(final HttpSession session) {
        session.removeAttribute("proceedContext");
    }

    /**
     * Updates the proceed context in session.
     *
     * @param session the session
     * @param proceedContext the ProceedContext
     */
    public static void updateSession(final HttpSession session, final ProceedContext proceedContext) {
        if (proceedContext != null) {
            session.setAttribute("proceedContext", proceedContext);
        }
    }

    /**
     * Fetches the proceedContext from session.
     *
     * @param session the session
     * @return ProceedContext
     */
    public static ProceedContext getProceedContextFromSession(final HttpSession session) {
        return (ProceedContext) session.getAttribute("proceedContext");
    }

    /**
     * Set the proceedContext in session for poll operation.
     *
     * @param session the session
     * @param proceedContext the ProceedContext
     */
    public static void setProceedContextForPoll(final HttpSession session, final ProceedContext proceedContext) {
        if (proceedContext != null) {
            session.setAttribute("proceedContextForPoll", proceedContext);
        }
    }

    /**
     * Fetches the proceedContext from session for poll operation.
     *
     * @param session the session
     * @return ProceedContext
     */
    public static ProceedContext getProceedContextForPoll(final HttpSession session) {
        return (ProceedContext) session.getAttribute("proceedContextForPoll");
    }

    /**
     * Construct RequestContext object with random `X-Device-Token` header value.
     *
     * @return request context object
     */
    public static RequestContext constructRequestContext() {
        final RequestContext requestContext = new RequestContext();
        // generate random str 32 char long
        final UUID randomUUID = UUID.randomUUID();
        final String randomString = randomUUID.toString().replaceAll("-", "");
        requestContext.setDeviceToken(randomString);
        return requestContext;
    }
}
