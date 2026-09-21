/*
 * Copyright (c) 2026-Present, Okta, Inc.
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
package com.okta.spring.example.http;

import com.okta.spring.example.helpers.Util;
import org.springframework.stereotype.Component;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Resolves the device token for every incoming request (reusing the browser's persisted
 * {@link Util#DEVICE_TOKEN_COOKIE_NAME} cookie, or minting and persisting a new one on first
 * visit) and publishes it via {@link CurrentDeviceToken} for the duration of the request.
 * Running this for every request - not just the initial {@code begin()} call - means every
 * IDX HTTP call made anywhere in a multi-step flow (verify, select-authenticator, poll, ...)
 * is attributed to the same device, not just the first one.
 */
@Component
public final class DeviceTokenFilter implements Filter {

    @Override
    public void doFilter(final ServletRequest request, final ServletResponse response, final FilterChain chain)
            throws IOException, ServletException {
        final HttpServletRequest httpRequest = (HttpServletRequest) request;
        final HttpServletResponse httpResponse = (HttpServletResponse) response;

        try {
            CurrentDeviceToken.set(Util.resolveDeviceToken(httpRequest, httpResponse));
            chain.doFilter(request, response);
        } finally {
            CurrentDeviceToken.clear();
        }
    }
}
