/*
 * Copyright 2021-Present Okta, Inc.
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

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Page {

    private static final int RETRY_COUNT = 15;

    protected WebDriver driver;

    private static A18NClient a18NClient;
    private static A18NProfile a18NProfile;
    private static User user;

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

    public Page(WebDriver driver) {
        this.driver = driver;
        PageFactory.initElements(driver, this);
    }

    public String getCurrentUrl() {
        return driver.getCurrentUrl();
    }

    public void waitForWebElementDisplayed(WebElement webElement) {
        new WebDriverWait(driver, 10)
                .until(ExpectedConditions.visibilityOf(webElement));
    }

    public String fetchCodeFromSMS() {
        String code = null;
        int retryCount = RETRY_COUNT;
        while (retryCount > 0 && code == null) {
            try { Thread.sleep(500); } catch (InterruptedException e) { e.printStackTrace(); }
            String sms = Page.getA18NClient().getLatestSmsContent(Page.getA18NProfile());
            code = StringUtils.substringBetween(sms, "code is ", ".");
            retryCount--;
        }
        return code;
    }

    public String fetchEmailContent() {
        String email = null;
        int retryCount = RETRY_COUNT;
        while(retryCount > 0) {
            try { Thread.sleep(500); } catch (InterruptedException e) { e.printStackTrace(); }
            email = Page.getA18NClient().getLatestEmailContent(Page.getA18NProfile());
            if(email != null) {
                break;
            } else {
                retryCount--;
            }
        }
        return email;
    }

    public String fetchCodeFromRegistrationEmail(String emailContent) {
        Pattern pattern = Pattern.compile("To verify manually, enter this code: (\\d{6})");
        Matcher matcher = pattern.matcher(emailContent);
        return matcher.find() ? matcher.group(1) : null;
    }

    public String fetchCodeFromPasswordResetEmail(String emailContent) {
        Pattern pattern = Pattern.compile("Enter a code instead: (\\d{6})");
        Matcher matcher = pattern.matcher(emailContent);
        return matcher.find() ? matcher.group(1) : null;
    }

    public void doNothing() {
        try { Thread.sleep(500); } catch (InterruptedException e) { e.printStackTrace(); }
    }
}
