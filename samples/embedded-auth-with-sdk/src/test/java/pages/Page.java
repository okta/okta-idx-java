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
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.support.PageFactory;

public class Page {

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

    public void sleep() {
        try {
            Thread.sleep(500);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }
}
