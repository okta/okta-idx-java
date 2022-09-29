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


import env.CucumberRoot;
import env.DriverUtil;
import io.cucumber.java.en.And;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import org.junit.Assert;
import org.openqa.selenium.WebDriver;
import pages.*;

public class SelfServicePasswordReset extends CucumberRoot {
    protected WebDriver driver = DriverUtil.getDefaultDriver();
    protected RootPage rootPage = new RootPage(driver);
    protected LoginPage loginPage = new LoginPage(driver);
    protected ProfilePage profilePage = new ProfilePage(driver);
    protected PasswordResetPage passwordResetPage = new PasswordResetPage(driver);

    @When("she clicks on the Forgot Password link")
    public void she_clicks_on_the_forgot_password_link() {
        loginPage.waitForWebElementDisplayed(passwordResetPage.forgotPasswordLink);
        Assert.assertTrue(passwordResetPage.forgotPasswordLink.isDisplayed());
        passwordResetPage.forgotPasswordLink.click();
    }

    @Then("^she sees the page to input the email address$")
    public void she_sees_the_page_to_input_the_email_address() {
        loginPage.waitForWebElementDisplayed(passwordResetPage.enterEmailBox);
        Assert.assertTrue(passwordResetPage.enterEmailBox.isDisplayed());
    }

    @And("^she submits the recovery form$")
    public void she_submits_the_recovery_form() {
        loginPage.waitForWebElementDisplayed(passwordResetPage.recoveryFormSubmitButton);
        Assert.assertTrue(passwordResetPage.recoveryFormSubmitButton.isDisplayed());
        passwordResetPage.recoveryFormSubmitButton.click();
    }

    @And("she clicks on \"Enter a code from the email instead\"")
    public void she_clicks_on_enter_a_code_from_the_email_instead() {
        loginPage.waitForWebElementDisplayed(passwordResetPage.codeEnterLink);
        Assert.assertTrue(passwordResetPage.codeEnterLink.isDisplayed());
        passwordResetPage.codeEnterLink.click();
    }

    @Then("^she sees a page to input her code$")
    public void she_sees_a_page_to_input_her_code() {
        loginPage.waitForWebElementDisplayed(passwordResetPage.enterCodeBox);
        Assert.assertTrue(passwordResetPage.enterCodeBox.isDisplayed());
        passwordResetPage.enterCodeBox.click();
    }

    @When("^she fills in the correct code$")
    public void she_fills_in_the_correct_code() {
        String emailContent = passwordResetPage.fetchEmailContent();
        Assert.assertNotNull(emailContent);
        String code = passwordResetPage.fetchCodeFromPasswordResetEmail(emailContent);
        Assert.assertNotNull(code);
        passwordResetPage.enterCodeBox.click();
        passwordResetPage.enterCodeBox.sendKeys(code);
    }

    @And("^she submits the form$")
    public void she_submits_the_form() {
        loginPage.submitButton.click();
    }

    @Then("^she sees a page to set her password$")
    public void she_sees_a_page_to_set_her_password() {
        loginPage.waitForWebElementDisplayed(passwordResetPage.newPasswordBox);
        Assert.assertTrue(passwordResetPage.newPasswordBox.isDisplayed());
    }

    @When("^she fills a password that fits within the password policy$")
    public void she_fills_a_password_that_fits_within_the_password_policy() {
        passwordResetPage.newPasswordBox.click();
        passwordResetPage.newPasswordBox.sendKeys("QwErTy@123");
    }

    @And("^she confirms that password$")
    public void she_confirms_that_password() {
        passwordResetPage.reEnterPasswordBox.click();
        passwordResetPage.reEnterPasswordBox.sendKeys("QwErTy@123");
    }

    @And("she submits the password reset form")
    public void she_submits_the_password_reset_form() {
        passwordResetPage.resetPasswordSubmitButton.click();
    }


    @When("she inputs her correct email address")
    public void she_inputs_her_correct_email_address() {
        Assert.assertNotNull(Page.getA18NProfile());
        Assert.assertNotNull(Page.getA18NProfile().getEmailAddress());
        Assert.assertNotNull(Page.getUser());
        String MailID=Page.getUser().getProfile().getEmail();
        driver.navigate().refresh();
        loginPage.waitForWebElementDisplayed(passwordResetPage.enterEmailBox);
        Assert.assertTrue(passwordResetPage.enterEmailBox.isDisplayed());
        passwordResetPage.enterEmailBox.sendKeys(MailID);
    }

    @And("^she sees a page saying \"Verify with your email\"$")
    public void she_sees_a_page_saying_verify_with_your_mail() {
        loginPage.waitForWebElementDisplayed(passwordResetPage.sendEmailButton);
        Assert.assertTrue(passwordResetPage.sendEmailButton.isDisplayed());
    }

    @Then("^she clicks on \"Send me an email\"$")
    public void she_clicks_on_send_me_an_email() {
        passwordResetPage.sendEmailButton.click();
    }

    @And("^the page changes to waiting screen message for email verification$")
    public void the_page_changes_to_waiting_screen_message_for_email_verification() {
        Assert.assertTrue(passwordResetPage.emailVerificationWaitingScreen.isDisplayed());
    }

}