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
package com.okta.idx.sdk.api.model;

import java.io.Serializable;
import java.time.Duration;
import java.time.temporal.ChronoUnit;

public class PollInfo implements Serializable {

    private static final long serialVersionUID = 2117736146706017782L;
    private String href;

    private Duration refresh;

    public PollInfo(String href, Duration refresh) {
        this.href = href;
        this.refresh = refresh;
    }

    public String getHref() {
        return href;
    }

    public void setHref(String href) {
        this.href = href;
    }

    public Duration getRefresh() {
        return Duration.of(refresh.getSeconds(), ChronoUnit.MILLIS);
    }

    public void setRefresh(Duration refresh) {
        this.refresh = refresh;
    }
}
