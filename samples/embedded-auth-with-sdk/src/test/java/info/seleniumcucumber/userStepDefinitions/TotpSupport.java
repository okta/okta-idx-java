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
package info.seleniumcucumber.userStepDefinitions;

import com.google.zxing.NotFoundException;
import env.CucumberRoot;
import env.DriverUtil;
import io.cucumber.java.en.And;
import io.cucumber.java.en.When;
import org.openqa.selenium.WebDriver;
import pages.QrCodePage;
import pages.SelectAuthenticatorPage;
import pages.VerifyPage;

import java.io.IOException;

public class TotpSupport extends CucumberRoot {

    protected WebDriver driver = DriverUtil.getDefaultDriver();
    private SelectAuthenticatorPage selectAuthenticatorPage = new SelectAuthenticatorPage(driver);
    private QrCodePage qrCodePage = new QrCodePage(driver);
    private VerifyPage verifyPage = new VerifyPage(driver);
    private String secret;

    @When("^she selects Google Authenticator from the list$")
    public void she_selects_google_authenticator_from_the_list() {
        selectAuthenticatorPage.googleAuthenticatorButton.click();
        selectAuthenticatorPage.proceedButton.click();
    }

    @And("she scans a QR Code")
    public void she_scans_a_qr_code() throws IOException, NotFoundException {
        qrCodePage.qrCode.isDisplayed();
        secret = QrCodePage.obtainSecret(qrCodePage.qrCode.getAttribute("src"));
    }


    @And("she selects \"Next\"")
    public void she_selects_Next() {
        qrCodePage.nextButton.click();
    }

    @When("^she inputs the correct code from her Google Authenticator App$")
    public void she_inputs_the_correct_code_from_her_google_authenticator_app() {
        verifyPage.codeInput.click();
        verifyPage.codeInput.sendKeys(QrCodePage.getOneTimePassword(secret));
    }
}
