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
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import org.apache.commons.lang3.StringUtils;
import org.junit.Assert;
import org.openqa.selenium.WebDriver;
import pages.*;

import java.util.ArrayList;

public class SelfServiceAccountUnlock extends CucumberRoot {

    protected WebDriver driver = DriverUtil.getDefaultDriver();
    protected RootPage rootPage = new RootPage(driver);
    protected LoginPage loginPage = new LoginPage(driver);
    protected ProfilePage profilePage = new ProfilePage(driver);
    protected Page page = new Page(driver);
    protected PasswordResetPage passwordResetPage = new PasswordResetPage(driver);
    protected AccountUnlockPage accountUnlockPage = new AccountUnlockPage(driver);

    @When("^she sees a link to unlock her account$")
    public void she_sees_a_link_to_unlock_her_account() {
        page.waitForOneSec();
        accountUnlockPage.waitForWebElementDisplayed(accountUnlockPage.unlockAccountLink);
        Assert.assertTrue(accountUnlockPage.unlockAccountLink.isDisplayed());
    }

    @And("^she clicks the link to unlock her account$")
    public void she_clicks_the_link_to_unlock_her_account() {
        page.waitForOneSec();
        accountUnlockPage.waitForWebElementDisplayed(accountUnlockPage.unlockAccountLink);
        accountUnlockPage.unlockAccountLink.click();
    }

    @Then("^she sees a page to input her username and select Email or Phone to unlock her account$")
    public void she_sees_a_page_to_input_her_username_and_select_email_or_phone_to_unlock_her_account() {
        accountUnlockPage.waitForWebElementDisplayed(accountUnlockPage.unlockAccountPage);
        Assert.assertTrue(accountUnlockPage.unlockAccountPage.isDisplayed());
    }

    @Then("^she selects Email from the available options$")
    public void she_selects_email_from_the_available_options() {
        Assert.assertTrue(accountUnlockPage.emailSelectButton.isDisplayed());
        accountUnlockPage.emailSelectButton.click();
    }

    @When("^she opens the magic link from her email inbox$")
    public void she_opens_the_magic_link_from_her_email_inbox() {
        String mailBody="email-activation-button";
        String emailContent = page.fetchSpecificEmailContent(mailBody);
        String magicLink = page.fetchUnlockMagicLinkFromEmail(emailContent);
        driver.get(magicLink);
    }

    @And("^she submits the verify form$")
    public void she_submits_the_form() {
        Assert.assertTrue(accountUnlockPage.verifyFormSubmitButton.isDisplayed());
        accountUnlockPage.verifyFormSubmitButton.click();
    }

    @Then("^she sees a page that says \"Account Successfully Unlocked!\" and to enter the password for verification$")
    public void she_sees_a_page_that_says_account_successfully_unlocked_and_to_enter_the_password_for_verification() {
        accountUnlockPage.waitForWebElementDisplayed(accountUnlockPage.accountUnlockSuccessMessage);
        Assert.assertTrue(accountUnlockPage.accountUnlockSuccessMessage.isDisplayed());
        Assert.assertTrue(accountUnlockPage.enterPasswordBox.isDisplayed());
    }
    @Then("^she selects \"Phone\" from the available options$")
    public void she_selects_phone_from_the_available_options() {
        Assert.assertTrue(accountUnlockPage.phoneSelectButton.isDisplayed());
        accountUnlockPage.phoneSelectButton.click();
    }

    @And("^she sees a page saying \"Verify with your phone\"$")
    public void she_sees_a_page_saying_verify_with_your_phone() {
        accountUnlockPage.waitForWebElementDisplayed(accountUnlockPage.receiveSMSButton);
        Assert.assertTrue(accountUnlockPage.receiveSMSButton.isDisplayed());
    }

    @Then("^she clicks the button saying \"Receive a code via SMS\"$")
    public void she_clicks_the_button_saying_receive_a_code_via_sms() {
        accountUnlockPage.receiveSMSButton.click();
    }

    @When("^she fills in the correct code from SMS$")
    public void she_fills_in_the_correct_code_from_sms() {
        String code = page.fetchCodeFromSMS();
        Assert.assertTrue(StringUtils.isNotBlank(code));
        passwordResetPage.enterCodeBox.click();
        passwordResetPage.enterCodeBox.sendKeys(code);
    }
}
