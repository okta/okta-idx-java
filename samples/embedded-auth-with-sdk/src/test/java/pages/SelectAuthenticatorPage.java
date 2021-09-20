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

import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.FindBy;

public class SelectAuthenticatorPage extends Page {

    public SelectAuthenticatorPage(WebDriver driver) {
        super(driver);
    }

    @FindBy(id = "phone")
    public WebElement phone;

    @FindBy(id = "submit-btn")
    public WebElement submitButton;

    @FindBy(className = "select-authenticators-form")
    public WebElement selectAuthenticatorsForm;

    @FindBy(css = "input[type='radio'][name='authenticator-type'][value='Email']")
    public WebElement emailRadioButton;

    @FindBy(css = "input[type='radio'][name='authenticator-type'][value='Google Authenticator']")
    public WebElement googleAuthenticatorButton;

    @FindBy(name = "code")
    public WebElement codeInput;

    @FindBy(id = "verify-btn")
    public WebElement verifyButton;

    @FindBy(id = "proceed-btn")
    public WebElement proceedButton;
}
