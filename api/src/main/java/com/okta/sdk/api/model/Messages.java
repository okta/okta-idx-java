package com.okta.sdk.api.model;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.okta.commons.lang.Strings;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY)
public class Messages {

    private String type;

    private MessageValue[] value;

    public MessageValue[] getValue() {
        return value;
    }

    public boolean hasErrorValue() {
        for (MessageValue messageValue : value) {
            String val = messageValue.getValue();
            if (Strings.hasText(val) && "ERROR".equals(val)) {
                return true;
            }
        }
        return false;
    }
}
