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

import com.okta.idx.sdk.api.client.ProceedContext;

import javax.servlet.http.HttpSession;

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
}
