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

import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.FindBy;

public class RootPage extends Page {

    public RootPage(WebDriver driver) {
        super(driver);
    }

    @FindBy(id = "login")
    public WebElement loginButton;

    @FindBy(id = "register")
    public WebElement registrationButton;

    @FindBy(id = "idToken")
    public WebElement idToken;

    @FindBy(id = "accessToken")
    public WebElement accessToken;

    @FindBy(id = "refreshToken")
    public WebElement refreshToken;

    @FindBy(id = "profileTable")
    public WebElement profileTable;

    @FindBy(id = "email")
    public WebElement email;

    @FindBy(className = "alert-danger")
    public WebElement alertDanger;

    public void navigateToTheRootPage() {
        driver.manage().window().maximize();
        driver.get("http://localhost:8080"); // TODO pass as env variable.
    }

    public boolean isLoginButtonDisplayed() {
        return loginButton.isDisplayed();
    }

    public boolean isRegistrationButtonDisplayed() {
        return registrationButton.isDisplayed();
    }
}
