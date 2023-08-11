package com.okta.idx.sdk.api.model;

import java.io.Serializable;

public class Age implements Serializable {

    private static final long serialVersionUID = 7791862517419185142L;

    private int historyCount;

    private int minAgeMinutes;

    public int getMinAgeMinutes() {
        return minAgeMinutes;
    }

    public void setMinAgeMinutes(int minAgeMinutes) {
        this.minAgeMinutes = minAgeMinutes;
    }

    public int getHistoryCount() {
        return historyCount;
    }

    public void setHistoryCount(int historyCount) {
        this.historyCount = historyCount;
    }
}
