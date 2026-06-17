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

public class AccountUnlockPage extends Page {

    public AccountUnlockPage(WebDriver driver) {
        super(driver);
    }

    @FindBy(css = "a[data-se = 'unlock']")
    public static WebElement unlockAccountLink;

    @FindBy(xpath = "//h2[text()= 'Unlock account?']")
    public static WebElement unlockAccountPage;

    @FindBy(css = "div[data-se = 'okta_email']")
    public static WebElement emailSelectButton;

    @FindBy(css = "input[type='submit'][value='Verify'][data-type='save']")
    public static WebElement verifyFormSubmitButton;

    @FindBy(className = "ion-messages-container")
    public static WebElement accountUnlockSuccessMessage;

    @FindBy(css = "input[type='password'][name='credentials.passcode']")
    public static WebElement enterPasswordBox;

    @FindBy(className = "otp-value")
    public static WebElement otpValue;

    @FindBy(css = "div[data-se = 'phone_number']")
    public static WebElement phoneSelectButton;

    @FindBy(css = "input[type='submit'][value='Receive a code via SMS']")
    public static WebElement receiveSMSButton;
}

