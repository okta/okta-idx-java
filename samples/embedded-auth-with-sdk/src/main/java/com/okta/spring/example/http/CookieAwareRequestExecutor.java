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

import com.okta.commons.http.DefaultResponse;
import com.okta.commons.http.HttpException;
import com.okta.commons.http.HttpHeaders;
import com.okta.commons.http.MediaType;
import com.okta.commons.http.Request;
import com.okta.commons.http.RequestExecutor;
import com.okta.commons.http.Response;
import com.okta.commons.http.authc.RequestAuthenticator;
import okhttp3.HttpUrl;
import okhttp3.OkHttpClient;
import okhttp3.RequestBody;
import okhttp3.ResponseBody;
import okio.BufferedSink;
import okio.Okio;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.SocketException;
import java.net.SocketTimeoutException;

/**
 * Sends requests through a caller-supplied {@link OkHttpClient} as-is, translating to/from
 * okta-commons-java's {@link Request}/{@link Response} types. Deliberately bypasses
 * okta-commons-java's own {@code OkHttpRequestExecutor}, whose {@code OkHttpClient} hardcodes
 * {@code CookieJar.NO_COOKIES} with no way to override it - see
 * {@link CookieAwareRequestExecutorFactory} for why that matters here.
 * <p>
 * Only supports the GET and POST methods the IDX API actually uses; not a general-purpose
 * replacement for the official executor.
 */
final class CookieAwareRequestExecutor implements RequestExecutor {

    /** The OkHttp client requests are sent through. */
    private final OkHttpClient client;

    /** Authenticates each request before it's sent, per the configured {@code HttpClientConfiguration}. */
    private final RequestAuthenticator requestAuthenticator;

    CookieAwareRequestExecutor(final OkHttpClient okHttpClient, final RequestAuthenticator authenticator) {
        this.client = okHttpClient;
        this.requestAuthenticator = authenticator;
    }

    @Override
    public Response executeRequest(final Request request) throws HttpException {
        requestAuthenticator.authenticate(request);

        final HttpUrl.Builder urlBuilder = HttpUrl.get(request.getResourceUrl()).newBuilder();
        request.getQueryString().forEach(urlBuilder::addQueryParameter);

        final okhttp3.Request.Builder okRequestBuilder = new okhttp3.Request.Builder().url(urlBuilder.build());
        request.getHeaders().toSingleValueMap().forEach(okRequestBuilder::addHeader);

        switch (request.getMethod()) {
            case GET:
                okRequestBuilder.get();
                break;
            case POST:
                okRequestBuilder.post(toRequestBody(request));
                break;
            default:
                throw new IllegalArgumentException(
                        "CookieAwareRequestExecutor only supports GET/POST, got: " + request.getMethod());
        }

        try {
            final okhttp3.Response okResponse = client.newCall(okRequestBuilder.build()).execute();
            return toSdkResponse(okResponse);
        } catch (SocketException | SocketTimeoutException e) {
            throw new HttpException("Unable to execute HTTP request - retryable exception: " + e.getMessage(), e, true);
        } catch (IOException e) {
            throw new HttpException(e.getMessage(), e);
        }
    }

    private static RequestBody toRequestBody(final Request request) {
        final okhttp3.MediaType contentType = okhttp3.MediaType.parse(request.getHeaders().getContentType().toString());
        final InputStream body = request.getBody();
        return new RequestBody() {
            @Override
            public okhttp3.MediaType contentType() {
                return contentType;
            }

            @Override
            public void writeTo(final BufferedSink sink) throws IOException {
                if (body != null) {
                    sink.writeAll(Okio.source(body));
                }
            }
        };
    }

    private static Response toSdkResponse(final okhttp3.Response okResponse) throws IOException {
        final HttpHeaders headers = new HttpHeaders();
        headers.putAll(okResponse.headers().toMultimap());
        final MediaType mediaType = headers.getContentType();

        final ResponseBody body = okResponse.body();
        InputStream bodyStream = null;
        long contentLength = 0;
        if (body != null) {
            final byte[] bytes = body.bytes();
            bodyStream = new ByteArrayInputStream(bytes);
            contentLength = bytes.length;
        }

        final Response response = new DefaultResponse(okResponse.code(), mediaType, bodyStream, contentLength);
        response.getHeaders().putAll(headers);
        return response;
    }
}
