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

public class PasswordResetPage extends Page {

    public PasswordResetPage(WebDriver driver) {
        super(driver);
    }

    @FindBy(css = "a[data-se='forgot-password']")
    public WebElement forgotPasswordLink;

    @FindBy(css = "input[type='text']")
    public WebElement enterEmailBox;

    @FindBy(css = "input[type='submit'][Value = 'Next']")
    public WebElement recoveryFormSubmitButton;

    @FindBy(className = "enter-auth-code-instead-link")
    public WebElement codeEnterLink;

    @FindBy(css = "input[type='text'][name='credentials.passcode']")
    public WebElement enterCodeBox;

    @FindBy(css = "input[type='password'][name='credentials.passcode']")
    public WebElement newPasswordBox;

    @FindBy(css = "input[type='password'][name='confirmPassword']")
    public WebElement reEnterPasswordBox;

    @FindBy(css = "input[type='submit'][value='Reset Password']")
    public WebElement resetPasswordSubmitButton;

    @FindBy(css = "input[type='submit'][value='Send me an email']")
    public WebElement sendEmailButton;

    @FindBy(className = "okta-form-subtitle")
    public WebElement emailVerificationWaitingScreen;

}
