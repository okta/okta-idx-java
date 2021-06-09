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
package info.seleniumcucumber.userStepDefinitions;

import env.CucumberRoot;
import env.DriverUtil;
import io.cucumber.java.en.And;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import org.apache.commons.lang3.StringUtils;
import org.junit.Assert;
import org.openqa.selenium.WebDriver;
import pages.*;

public class MFA extends CucumberRoot {

    protected WebDriver driver = DriverUtil.getDefaultDriver();
    private LoginPage loginPage = new LoginPage(driver);
    private VerifyPage verifyPage = new VerifyPage(driver);
    private SelectAuthenticatorPage selectAuthenticatorPage = new SelectAuthenticatorPage(driver);
    private RegisterPage registerPage = new RegisterPage(driver);

    @When("^she fills in her correct username for mfa$")
    public void she_fills_in_her_correct_username_for_mfa() {
        loginPage.waitForWebElementDisplayed(loginPage.usernameInput);
        Assert.assertTrue(loginPage.usernameInput.isDisplayed());
        loginPage.usernameInput.click();
        loginPage.usernameInput.sendKeys(Page.getUser().getProfile().getEmail());
    }

    @And("^she fills in her correct password for mfa$")
    public void she_fills_in_her_correct_password_for_mfa() {
        loginPage.passwordInput.click();
        loginPage.passwordInput.sendKeys("Abcd1234");
    }

    @Then("^she is presented with a list of factors$")
    public void she_is_presented_with_a_list_of_factors() {
        Assert.assertTrue(verifyPage.phoneRadioButton.isDisplayed());
    }

    @Then("^she is presented with an option to select Email to verify$")
    public void she_is_presented_with_an_option_to_select_email_to_verify() {
        Assert.assertTrue(selectAuthenticatorPage.selectAuthenticatorsForm.isDisplayed());
        Assert.assertTrue(selectAuthenticatorPage.emailRadioButton.isDisplayed());
    }

    @And("^she inputs the incorrect code from the email$")
    @And("^she inputs the incorrect code from the phone$")
    public void she_inputs_the_incorrect_code(){
        selectAuthenticatorPage.codeInput.click();
        selectAuthenticatorPage.codeInput.sendKeys("invalid_code");
        selectAuthenticatorPage.verifyButton.click();
    }

    @And("^she inputs a invalid phone number$")
    public void she_inputs_a_invalid_phone_number() {
        selectAuthenticatorPage.waitForWebElementDisplayed(selectAuthenticatorPage.phone);
        Assert.assertTrue(selectAuthenticatorPage.phone.isDisplayed());
        selectAuthenticatorPage.phone.click();
        selectAuthenticatorPage.phone.sendKeys(Page.getA18NProfile().getPhoneNumber());
    }

    @Then("^the screen changes to receive an input for a code$")
    public void the_screen_changes_to_receive_an_input_for_a_code() {
        Assert.assertTrue(registerPage.codeInput.isDisplayed());
    }

    @When("^she inputs the correct code from the SMS$")
    public void she_inputs_the_correct_code_from_the_sms() {
        String code = registerPage.fetchCodeFromSMS();
        Assert.assertTrue(StringUtils.isNotBlank(code));
        registerPage.codeInput.click();
        registerPage.codeInput.sendKeys(code);
    }

    @Then("^the sample shows an error message \"Invalid code. Try again.\" on the Sample App$")
    public void the_sample_shows_an_error_message(){
        registerPage.waitForWebElementDisplayed(registerPage.alertDanger);
        Assert.assertTrue(registerPage.alertDanger.isDisplayed());
        String error = registerPage.alertDanger.getText();
        Assert.assertFalse("Error is not shown", error.isEmpty());
        Assert.assertTrue("Invalid code error is not shown", error.contains("Invalid code. Try again."));
    }

    @Then("^she should see a message \"Unable to initiate factor enrollment: Invalid Phone Number\"$")
    public void she_should_see_a_message_invalid_phone_number() {
        registerPage.waitForWebElementDisplayed(registerPage.alertDanger);
        Assert.assertTrue(registerPage.alertDanger.isDisplayed());
        String error = registerPage.alertDanger.getText();
        Assert.assertFalse("Error is not shown", error.isEmpty());
        Assert.assertTrue("Invalid phone number error is not shown",
                error.contains("Unable to initiate factor enrollment: Invalid Phone Number"));
    }

    @And("^she sees a field to re-enter another code$")
    public void she_sees_a_field_to_reenter_another_code(){
        Assert.assertTrue(selectAuthenticatorPage.codeInput.isDisplayed());
    }
}
