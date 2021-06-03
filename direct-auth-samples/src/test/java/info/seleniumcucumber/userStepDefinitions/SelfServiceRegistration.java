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

import io.cucumber.java.en.And;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import env.CucumberRoot;
import env.DriverUtil;
import env.a18n.client.response.A18NEmail;
import org.junit.Assert;
import org.openqa.selenium.WebDriver;
import pages.Page;
import pages.RegisterPage;
import pages.RegisterPhonePage;
import pages.SelectAuthenticatorPage;
import pages.VerifyPage;

public class SelfServiceRegistration extends CucumberRoot {

    private static final int RETRY_COUNT = 5; //TODO Should be in config

    protected WebDriver driver = DriverUtil.getDefaultDriver();

    private RegisterPage registerPage = new RegisterPage(driver);
    private RegisterPhonePage registerPhonePage = new RegisterPhonePage(driver);
    private SelectAuthenticatorPage selectAuthenticatorPage = new SelectAuthenticatorPage(driver);
    private VerifyPage verifyPage = new VerifyPage(driver);

    @When("^she fills out her First Name$")
    public void she_fills_out_her_first_name() {
        registerPage.sleep();
        registerPage.firstnameInput.click();
        registerPage.firstnameInput.sendKeys("Mary");
    }

    @And("^she fills out her Last Name$")
    public void she_fills_out_her_last_name() {
        String profileSuffix = "self-service-registration";
        if(Page.getA18NProfile() != null && Page.getA18NProfile().getProfileId() != null) {
            profileSuffix = Page.getA18NProfile().getProfileId();
        }
        registerPage.lastnameInput.click();
        registerPage.lastnameInput.sendKeys("e2e-" + profileSuffix);
    }

    @And("^she fills out her Email$")
    public void she_fills_out_her_email() {
        Assert.assertNotNull(Page.getA18NProfile());
        Assert.assertNotNull(Page.getA18NProfile().getEmailAddress());
        registerPage.emailInput.click();
        registerPage.emailInput.sendKeys(Page.getA18NProfile().getEmailAddress());
    }

    @And("^she fills out her Email with an invalid email format$")
    public void she_fills_out_her_email_with_an_invalid_email_format() {
        registerPage.emailInput.click();
        registerPage.emailInput.sendKeys("e2e-ssr@acme");
    }

    @And("^she submits the registration form$")
    public void she_submits_the_registration_form() {
        registerPage.sleep();
        registerPage.signInButton.click();
    }

    @Then("^she sees a list of required factors to setup$")
    public void she_sees_a_list_of_required_factors_to_setup() {
        registerPage.sleep();
        //Assert.assertTrue(registerPage.codeInput.isDisplayed());
    }

    @When("^she selects Email$")
    public void she_selects_email() {
        registerPage.sleep();
        registerPage.emailRadioButton.click();
        registerPage.proceedButton.click();
    }

    @Then("^she sees a page to input a code$")
    public void she_sees_a_page_to_input_a_code() {
        registerPage.sleep();
        Assert.assertTrue(registerPage.codeInput.isDisplayed());
    }

    @When("^she inputs the correct code from her email$")
    public void she_inputs_the_correct_code_from_her_email() {
        A18NEmail email = null;
        String code;
        int retryCount = RETRY_COUNT;
        while(retryCount > 0) {
            registerPage.sleep();
            email = Page.getA18NClient().getLatestEmail(Page.getA18NProfile());
            if(email != null && email.getContent() != null) {
                break;
            } else {
                retryCount--;
            }
        }
        Assert.assertNotNull(email);
        code = email.fetchCodeFromRegistrationEmail();
        Assert.assertNotNull(code);
        registerPage.codeInput.click();
        registerPage.codeInput.sendKeys(code);
    }

    @And("^she submits the verify form$")
    public void she_submits_the_verify_form() {
        registerPage.verifyButton.click();
    }

    @When("^she selects Password$")
    public void she_selects_password() {
        registerPage.sleep();
        registerPage.passwordRadioButton.click();
        registerPage.proceedButton.click();
    }

    @Then("^she sees a page to setup password$")
    public void she_sees_a_page_to_setup_password() {
        registerPage.sleep();
        Assert.assertTrue(registerPage.newPasswordInput.isDisplayed());
        Assert.assertTrue(registerPage.confirmNewPasswordInput.isDisplayed());
    }

    @When("^she fills out her Password$")
    public void she_fills_out_her_password() {
        registerPage.sleep();
        registerPage.newPasswordInput.click();
        registerPage.newPasswordInput.sendKeys("QwErTy@123");
    }

    @And("^she confirms her Password$")
    public void she_confirms_her_password() {
        registerPage.confirmNewPasswordInput.click();
        registerPage.confirmNewPasswordInput.sendKeys("QwErTy@123");
    }

    @Then("^she sees the list of optional factors$")
    public void she_sees_the_list_of_optional_factors_sms() {
        registerPage.sleep();
    }

    @When("^she selects \"Skip\" on SMS$")
    public void she_selects_skip_on_sms() {
        registerPage.sleep();
        registerPage.skipButton.click();
    }

    @And("^an application session is created$")
    public void an_application_session_is_created() {
        Assert.assertTrue(registerPage.profileTable.isDisplayed());
    }

    @Then("^she sees an error message \"'Email' must be in the form of an email address, Provided value for property 'Email' does not match required pattern\"$")
    public void she_sees_an_error_message_email_invalid() {
        registerPage.sleep();
        Assert.assertTrue(registerPage.alertDanger.isDisplayed());
        String error = registerPage.alertDanger.getText();
        Assert.assertFalse("Error is not shown", error.isEmpty());
        Assert.assertTrue("No account with username error is not shown'",
                error.contains("Provided value for property 'Email' does not match required pattern"));
    }


    @Then("she is redirected back to the Root View")
    public void she_is_redirected_back_to_the_root_view() {
        driver.getCurrentUrl().equals("http://localhost:8080");// TODO make through env var.
    }

    @Then("^she sees a list of factors to register$")
    public void she_sees_a_list_of_factors_to_register() {
        Assert.assertTrue(verifyPage.phoneRadioButton.isDisplayed());
    }

    @When("^she selects Phone from the list$")
    public void she_selects_phone_from_the_list() {
        verifyPage.phoneRadioButton.click();
        verifyPage.proceedButton.click();
    }

    @And("^she inputs an invalid phone number$")
    public void she_inputs_an_invalid_phone_number () {
        Assert.assertTrue(selectAuthenticatorPage.phone.isDisplayed());
        selectAuthenticatorPage.phone.click();
        selectAuthenticatorPage.phone.sendKeys("+333333333333");
    }

    @And("^submits the enrollment form$")
    public void submits_the_enrollment_form() {
        selectAuthenticatorPage.submitButton.click();
    }

    @Then("^she sees a list of phone modes$")
    public void she_sees_a_list_of_phone_modes() {
        Assert.assertTrue(registerPhonePage.smsRadioButton.isDisplayed());
    }

    @When("^she selects SMS$")
    public void she_selects_sms() {
        registerPhonePage.smsRadioButton.click();
    }

    @And("^she submits the phone mode form$")
    public void she_submits_the_phone_mode_form() {
        registerPhonePage.submitButton.click();
    }

    @Then("^she should see an error message \"Unable to initiate factor enrollment: Invalid Phone Number.\"$")
    public void she_should_see_an_error_message_invalid_phone_number() {
        Assert.assertTrue(registerPhonePage.alertDanger.isDisplayed());
        String error = registerPhonePage.alertDanger.getText();
        Assert.assertFalse("Error is not shown", error.isEmpty());
        Assert.assertTrue("Invalid phone number error is not shown'",
                error.contains("Unable to initiate factor enrollment: Invalid Phone Number."));
    }


}
