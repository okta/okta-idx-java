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

public class OktaVerifyPage extends Page {

    public OktaVerifyPage(WebDriver driver) {
        super(driver);
    }

    @FindBy(css = "input[type='radio'][name='authenticator-type'][value='okta_verify']")
    public WebElement oktaVerifyRadioButton;

    @FindBy(className="switch-channel-link")
    public WebElement optionsLink;

    @FindBy(css = "input[type='radio'][name='mode'][value='email'][class='form-check-input']")
    public WebElement emailModeRadioButton;

    @FindBy(css = "input[type='radio'][name='mode'][value='sms'][class='form-check-input']")
    public WebElement smsModeRadioButton;

    @FindBy(className="text-center")
    public WebElement waitingScreen;

    @FindBy(css = "input[type='text'][name='channelValue'][required='required']")
    public WebElement phoneOrEmailTextBox;

    @FindBy(className="okta-verify-desc-text")
    public WebElement oktaVerifyScreen;

    @FindBy(id = "select-factor-ov-form")
    public WebElement authenticatorsOption;

}
