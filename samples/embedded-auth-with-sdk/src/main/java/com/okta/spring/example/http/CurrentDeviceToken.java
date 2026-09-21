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

/**
 * Holds the device token for the browser making the current HTTP request. This app is a
 * multi-user server, and {@link CookieAwareRequestExecutorFactory} builds one shared HTTP
 * client for the lifetime of the app, so the device token to attach to an outgoing IDX call
 * can't be baked in at client-construction time - it has to be resolved per request. {@code
 * DeviceTokenFilter} sets this once per request and clears it when the request completes;
 * {@code CookieAwareRequestExecutorFactory}'s interceptor reads it for every IDX call made
 * while handling that request.
 */
public final class CurrentDeviceToken {

    /** Holds the device token for the request being processed on this thread. */
    private static final ThreadLocal<String> HOLDER = new ThreadLocal<>();

    private CurrentDeviceToken() {
    }

    /**
     * Sets the device token for the request being handled on the current thread.
     *
     * @param deviceToken the device token
     */
    public static void set(final String deviceToken) {
        HOLDER.set(deviceToken);
    }

    /**
     * Gets the device token for the request being handled on the current thread, or
     * {@code null} if none has been set (e.g. outside of a request).
     *
     * @return the device token, or {@code null}
     */
    public static String get() {
        return HOLDER.get();
    }

    /**
     * Clears the device token for the current thread. Must be called when the request
     * finishes so the value isn't leaked into whatever the thread handles next.
     */
    public static void clear() {
        HOLDER.remove();
    }
}
