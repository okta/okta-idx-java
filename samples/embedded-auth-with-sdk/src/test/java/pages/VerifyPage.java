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

public class VerifyPage extends Page {

    public VerifyPage(WebDriver driver) {
        super(driver);
    }

    @FindBy(name = "code")
    public WebElement codeInput;

    @FindBy(id = "verify-btn")
    public WebElement verifyButton;

    @FindBy(css = "input[name='authenticator-type'][value='phone']")
    public WebElement phoneRadioButton;

    @FindBy(id = "proceed-btn")
    public WebElement proceedButton;

    //Added for webauthn
    @FindBy(css = "input[name='authenticator-type'][value='webauthn']")
    public WebElement webAuthnRadioButton;
}
