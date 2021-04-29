package com.okta.spring.example.helpers;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Util {

    /**
     * Validates if the supplied phone number is a valid international number.
     *
     * @param phoneNumber the phone number
     * @return true if valid; false otherwise
     */
    public static boolean isValidPhoneNumber(final String phoneNumber) {
        Pattern pattern = Pattern.compile("^\\+(?:[0-9] ?){6,14}[0-9]$");
        Matcher matcher = pattern.matcher(phoneNumber);
        return (matcher.find() && matcher.group().equals(phoneNumber));
    }
}
