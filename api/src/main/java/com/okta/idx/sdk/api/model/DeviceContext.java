package com.okta.idx.sdk.api.model;

import java.util.HashMap;
import java.util.Map;

public class DeviceContext {

    public final static String USER_AGENT = "User-Agent";
    public final static String X_OKTA_USER_AGENT_EXTENDED = "X-Okta-User-Agent-Extended";
    public final static String X_DEVICE_TOKEN = "X-Device-Token";
    public final static String X_FORWARDED_FOR = "X-Forwarded-For";

    /**
     * store key value pairs of header name -> header value
     */
    private final Map<String, String> params = new HashMap<>();

    public DeviceContext addParam(String name, String value) {
        params.put(name, value);
        return this;
    }

    public String getParam(String name) {
        return params.get(name);
    }

    public Map<String, String> getAll() {
        return new HashMap<>(params);
    }
}
