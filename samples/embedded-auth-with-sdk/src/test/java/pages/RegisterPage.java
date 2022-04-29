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

public class RegisterPage extends Page {

    public RegisterPage(WebDriver driver) {
        super(driver);
    }

    @FindBy(id = "firstName")
    public WebElement firstNameInput;

    @FindBy(id = "lastName")
    public WebElement lastNameInput;

    @FindBy(id = "email")
    public WebElement emailInput;

    @FindBy(id = "sign-in-btn")
    public WebElement signInButton;

    @FindBy(css = "input[name='authenticator-type'][value='email']")
    public WebElement emailRadioButton;

    @FindBy(css = "input[name='authenticator-type'][value='password']")
    public WebElement passwordRadioButton;

    @FindBy(css = "input[name='authenticator-type'][value='security_question']")
    public WebElement securityQuestionRadioButton;

    @FindBy(css = "select[name='security_question_key'][id='questions']")
    public WebElement securityQuestionKey;

    @FindBy(css = "option[value='disliked_food']")
    public WebElement dislikedFoodSecurityQuestionKey;

    @FindBy(css = "input[name='code'][id='answer']")
    public WebElement securityQuestionAnswer;

    @FindBy(name = "new-password")
    public WebElement newPasswordInput;

    @FindBy(name = "confirm-new-password")
    public WebElement confirmNewPasswordInput;

    @FindBy(id = "proceed-btn")
    public WebElement proceedButton;

    @FindBy(name = "code")
    public WebElement codeInput;

    @FindBy(id = "verify-btn")
    public WebElement verifyButton;

    @FindBy(id = "skip-btn")
    public WebElement skipButton;

    @FindBy(id = "profileTable")
    public WebElement profileTable;

    @FindBy(className = "alert-danger")
    public WebElement alertDanger;
}
