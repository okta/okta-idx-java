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
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import org.openqa.selenium.WebDriver;
import pages.Page;
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

    @Then("^she is presented with an option to select Google Authenticator to verify$")
    @Then("^she sees the list of required factors \\(Google Authenticator\\) to enroll$")
    public void she_sees_the_required_google_authenticator_to_enroll() {
        selectAuthenticatorPage.googleAuthenticatorButton.isDisplayed();
    }

    @When("^she selects Google Authenticator from the list$")
    public void she_selects_google_authenticator_from_the_list() {
        selectAuthenticatorPage.googleAuthenticatorButton.click();
        selectAuthenticatorPage.proceedButton.click();
    }

    @Then("she sees a screen which shows a QR code and a shared secret key")
    public void she_sees_a_screen_which_shows_a_qr_code_and_a_shared_secret_key() {
        qrCodePage.qrCode.isDisplayed();
        qrCodePage.secretKey.isDisplayed();
    }
    
    @And("she scans a QR Code")
    public void she_scans_a_qr_code() throws IOException, NotFoundException {
        secret = QrCodePage.obtainSecret(qrCodePage.qrCode.getAttribute("src"));
    }

    @And("she enters the shared Secret Key into the Google Authenticator App")
    public void she_enters_the_shared_secret_key_into_the_google_authenticator_app() {
        secret = qrCodePage.secretKey.getText();
    }

    @And("she selects \"Next\"")
    @And("she selects \"Next\" on the screen which is showing the QR code")
    public void she_selects_Next() {
        qrCodePage.nextButton.click();
    }

    @When("^she inputs the correct code from her Google Authenticator App$")
    public void she_inputs_the_correct_code_from_her_google_authenticator_app() {
        verifyPage.codeInput.click();
        verifyPage.codeInput.sendKeys(QrCodePage.getOneTimePassword(secret));
    }
    @When("^she inputs the correct code from the Google Authenticator$")
    public void she_inputs_the_correct_code_from_the_google_authenticator() {
        verifyPage.codeInput.click();
        verifyPage.codeInput.sendKeys(QrCodePage.getOneTimePassword(Page.getTotpSharedSecret()));
    }
}
