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

import com.okta.commons.http.RequestExecutor;
import com.okta.commons.http.RequestExecutorFactory;
import com.okta.commons.http.RetryRequestExecutor;
import com.okta.commons.http.config.HttpClientConfiguration;
import okhttp3.OkHttpClient;

import java.util.concurrent.TimeUnit;

/**
 * Attaches a {@code DT} cookie built from the current request's persisted device token (see
 * {@link CurrentDeviceToken}) to every outgoing IDX call, so Okta can recognize a returning
 * device the same way it would from a browser holding its own {@code DT} cookie.
 * <p>
 * This exists because okta-idx-java only ever sends the device token as an {@code X-Device-Token}
 * header (via {@code RequestContext.setDeviceToken}), but Okta's known-device check for the
 * self-service-unlock flow only looks at a {@code DT} cookie - it never reads that header. And
 * okta-commons-java's own {@code OkHttpRequestExecutor} can't help either: its {@code OkHttpClient}
 * hardcodes {@code CookieJar.NO_COOKIES} with no supported way to override it.
 * <p>
 * Registered as the sole {@code META-INF/services} provider for {@link RequestExecutorFactory} in
 * this sample (with {@code okta-http-okhttp} excluded from the {@code okta-idx-java-api} dependency
 * in {@code pom.xml}, so {@code ServiceLoader} doesn't also find okta-commons-java's own factory).
 */
public final class CookieAwareRequestExecutorFactory implements RequestExecutorFactory {

    /** Name of the cookie Okta itself uses to remember a device across sign-ins. */
    private static final String DEVICE_TOKEN_COOKIE_NAME = "DT";

    @Override
    public RequestExecutor create(final HttpClientConfiguration configuration) {
        final OkHttpClient client = new OkHttpClient.Builder()
                .connectTimeout(configuration.getConnectionTimeout(), TimeUnit.SECONDS)
                .readTimeout(configuration.getConnectionTimeout(), TimeUnit.SECONDS)
                .writeTimeout(configuration.getConnectionTimeout(), TimeUnit.SECONDS)
                .addInterceptor(chain -> {
                    final String deviceToken = CurrentDeviceToken.get();
                    if (deviceToken == null) {
                        return chain.proceed(chain.request());
                    }
                    return chain.proceed(chain.request().newBuilder()
                            .addHeader("Cookie", DEVICE_TOKEN_COOKIE_NAME + "=" + deviceToken)
                            .build());
                })
                .build();

        final RequestExecutor executor = new CookieAwareRequestExecutor(client, configuration.getRequestAuthenticator());
        return new RetryRequestExecutor(configuration, executor);
    }
}
