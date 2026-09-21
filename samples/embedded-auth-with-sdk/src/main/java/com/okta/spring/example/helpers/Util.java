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

import com.okta.commons.lang.Strings;
import com.okta.idx.sdk.api.client.ProceedContext;
import com.okta.idx.sdk.api.model.RequestContext;
import com.okta.spring.example.http.CurrentDeviceToken;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.time.Duration;
import java.util.UUID;

public final class Util {

    /**
     * Name of the cookie this sample uses to persist a device token across requests from the
     * same browser, so the same {@code X-Device-Token} value is sent on every request instead
     * of a new one every time.
     */
    public static final String DEVICE_TOKEN_COOKIE_NAME = "okta-sample-device-token";

    /**
     * Lifetime, in days, of the persisted device token cookie. Mirrors the ~2 year
     * lifetime of Okta's own device (DT) cookie.
     */
    private static final int DEVICE_TOKEN_COOKIE_MAX_AGE_DAYS = 730;

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
     * Resolves the device token for the current request: reuses the value already persisted in
     * {@link #DEVICE_TOKEN_COOKIE_NAME} if the browser already has one, otherwise mints a new one
     * and persists it for future requests. Called once per request by {@code DeviceTokenFilter},
     * which publishes the result via {@code CurrentDeviceToken} for the rest of the request.
     *
     * @param request the servlet request, checked for an existing device token cookie
     * @param response the servlet response, used to persist a newly generated device token
     * @return the device token to use for this request
     */
    public static String resolveDeviceToken(final HttpServletRequest request, final HttpServletResponse response) {
        final String existing = readDeviceTokenCookie(request);
        return Strings.hasText(existing) ? existing : generateAndPersistDeviceToken(response);
    }

    private static String readDeviceTokenCookie(final HttpServletRequest request) {
        final Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return null;
        }
        for (final Cookie cookie : cookies) {
            if (DEVICE_TOKEN_COOKIE_NAME.equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return null;
    }

    /**
     * Generates a new device token and persists it in a long-lived cookie so subsequent requests
     * from the same browser reuse it, mirroring the ~2 year lifetime of Okta's own device (DT) cookie.
     *
     * @param response the servlet response to set the cookie on
     * @return the newly generated device token
     */
    private static String generateAndPersistDeviceToken(final HttpServletResponse response) {
        // generate random str 32 char long
        final UUID randomUUID = UUID.randomUUID();
        final String deviceToken = randomUUID.toString().replaceAll("-", "");

        final ResponseCookie cookie = ResponseCookie.from(DEVICE_TOKEN_COOKIE_NAME, deviceToken)
                .httpOnly(true)
                .path("/")
                .maxAge(Duration.ofDays(DEVICE_TOKEN_COOKIE_MAX_AGE_DAYS))
                .sameSite("Lax")
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());

        return deviceToken;
    }

    /**
     * Construct a RequestContext carrying the current request's device token (see
     * {@link #resolveDeviceToken}) as the {@code X-Device-Token} header.
     *
     * @return request context object
     */
    public static RequestContext constructRequestContext() {
        final RequestContext requestContext = new RequestContext();
        final String deviceToken = CurrentDeviceToken.get();
        if (Strings.hasText(deviceToken)) {
            requestContext.setDeviceToken(deviceToken);
        }
        return requestContext;
    }
}
