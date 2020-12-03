/*
 * Copyright 2020-Present Okta, Inc.
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
package com.okta.sdk.api.exception;

import com.okta.sdk.api.response.ErrorResponse;

public class ProcessingException extends Exception {

    private int httpStatus;
    private transient ErrorResponse errorResponse;

    public ProcessingException(int httpStatus, String message) {
        super(message + " HTTP status: " + httpStatus);
        this.httpStatus = httpStatus;
    }

    public ProcessingException(Throwable cause) {
        super(cause);
    }

    public ProcessingException(int httpStatus, String message, ErrorResponse errorResponse) {
        super(message + " HTTP status: " + httpStatus);
        this.httpStatus = httpStatus;
        this.errorResponse = errorResponse;
    }

    public ErrorResponse getErrorResponse() {
        return errorResponse;
    }

    public int getHttpStatus() {
        return httpStatus;
    }
}
