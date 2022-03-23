/*
 * Copyright (c) 2021-Present, Okta, Inc.
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
package pages;

import com.okta.sdk.resource.user.User;
import env.a18n.client.A18NClient;
import env.a18n.client.response.A18NProfile;
import org.apache.commons.lang3.StringUtils;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.PageFactory;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Page {

    private final Logger logger = LoggerFactory.getLogger(Page.class);

    private static final int TIME_OUT_IN_SECONDS = 20;

    protected WebDriver driver;

    private static A18NClient a18NClient;
    private static A18NProfile a18NProfile;
    private static User user;
    private static String totpSharedSecret;

    public static A18NClient getA18NClient() {
        return a18NClient;
    }

    public static void setA18NClient(A18NClient a18NClient) {
        Page.a18NClient = a18NClient;
    }

    public static A18NProfile getA18NProfile() {
        return a18NProfile;
    }

    public static void setA18NProfile(A18NProfile a18NProfile) {
        Page.a18NProfile = a18NProfile;
    }

    public static User getUser() {
        return user;
    }

    public static void setUser(User user) {
        Page.user = user;
    }

    public static String getTotpSharedSecret() {
        return totpSharedSecret;
    }

    public static void setTotpSharedSecret(String totpSharedSecret) {
        Page.totpSharedSecret = totpSharedSecret;
    }

    public Page(WebDriver driver) {
        this.driver = driver;
        PageFactory.initElements(driver, this);
    }

    public String getCurrentUrl() {
        return driver.getCurrentUrl();
    }

    public void waitForWebElementDisplayed(WebElement webElement) {
        new WebDriverWait(driver, TIME_OUT_IN_SECONDS)
                .until(ExpectedConditions.visibilityOf(webElement));
    }

    public String fetchCodeFromSMS() {
        String code = null;
        int totalRetryCount = getRetryCountDuringVerificationCodeFetching();
        int tryCounter = 0;
        while (tryCounter < totalRetryCount && code == null) {
            waitForNextTry();
            String sms = Page.getA18NClient().getLatestSmsContent(Page.getA18NProfile());
            code = StringUtils.substringBetween(sms, "code is ", ".");
            if(code == null) {
                logger.warn("Attempt {} of {} SMS fetching failed.", tryCounter, totalRetryCount);
            } else {
                logger.info("Verification SMS successfully received.");
            }
            tryCounter++;
        }
        return code;
    }

    public String fetchEmailContent() {
        String email = null;
        int totalRetryCount = getRetryCountDuringVerificationCodeFetching();
        int tryCounter = 0;
        while(tryCounter < totalRetryCount && email == null) {
            waitForNextTry();
            email = Page.getA18NClient().getLatestEmailContent(Page.getA18NProfile());
            if(email == null) {
                logger.warn("Attempt {} of {} email fetching failed.", tryCounter, totalRetryCount);
            } else {
                logger.info("Verification email successfully received.");
            }
            tryCounter++;
        }
        return email;
    }

    public String fetchCodeFromRegistrationEmail(String emailContent) {
        Pattern pattern = Pattern.compile("To verify manually, enter this code: (\\d{6})");
        Matcher matcher = pattern.matcher(emailContent);
        return matcher.find() ? matcher.group(1) : null;
    }

    private void waitForNextTry() {
        try {
            Thread.sleep(getSleepDurationDuringVerificationCodeFetching());
        } catch (InterruptedException e) {
            logger.error("Exception occurred", e);
        }
    }

    public String fetchCodeFromPasswordResetEmail(String emailContent) {
        Pattern pattern = Pattern.compile("Enter a code instead: (\\d{6})");
        Matcher matcher = pattern.matcher(emailContent);
        return matcher.find() ? matcher.group(1) : null;
    }

    public String fetchMagicLinkFromEmail(String emailContent) {
        Pattern pattern = Pattern.compile("\\\"email-authentication-button\\\" href=\\\"(.*?)\\\"");
        Matcher matcher = pattern.matcher(emailContent);
        return matcher.find() ? matcher.group(1) : null;
    }

    int getRetryCountDuringVerificationCodeFetching() {
        int retry = 5;
        try {
            retry = Integer.parseInt(
                    System.getenv().getOrDefault("OKTA_E2E_VERIFICATION_CODE_RETRY_COUNT", retry + "")
            );
        } catch (NumberFormatException e) {
            logger.warn("Fail to parse OKTA_E2E_VERIFICATION_CODE_RETRY_COUNT. Defaulting to {}.", retry, e);
        }

        return retry;
    }

    int getSleepDurationDuringVerificationCodeFetching() {
        int value = 4000;
        try {
            value = Integer.parseInt(
                    System.getenv().getOrDefault("OKTA_E2E_VERIFICATION_CODE_SLEEP_DURATION", value + "")
            );
        } catch (NumberFormatException e) {
            logger.warn("Fail to parse OKTA_E2E_VERIFICATION_CODE_SLEEP_DURATION. Defaulting to {}.", value, e);
        }

        return value;
    }
}
