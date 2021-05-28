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

import cucumber.api.java.en.Given;
import cucumber.api.java.en.And;
import cucumber.api.java.en.Then;
import cucumber.api.java.en.When;
import env.CucumberRoot;
import env.DriverUtil;
import env.a18n.client.response.A18NEmail;
import org.junit.Assert;
import org.openqa.selenium.WebDriver;
import pages.Page;
import pages.RegisterPage;
import pages.RootPage;

public class SelfServiceRegistration extends CucumberRoot {

    protected WebDriver driver = DriverUtil.getDefaultDriver();

    private RootPage rootPage = new RootPage(driver);
    private RegisterPage registerPage = new RegisterPage(driver);

    @When("she fills out her First Name")
    public void sheFillsOutHerFirstName() {
        registerPage.sleep();
        registerPage.firstnameInput.click();
        registerPage.firstnameInput.sendKeys("Mary");
    }

    @And("she fills out her Last Name")
    public void sheFillsOutHerLastName() {
        Assert.assertNotNull(Page.getA18NProfile());
        Assert.assertNotNull(Page.getA18NProfile().getProfileId());
        registerPage.lastnameInput.click();
        registerPage.lastnameInput.sendKeys("e2e-ssr-" + Page.getA18NProfile().getProfileId());
    }

    @And("she fills out her Email")
    public void sheFillsOutHerEmail() {
        Assert.assertNotNull(Page.getA18NProfile());
        Assert.assertNotNull(Page.getA18NProfile().getEmailAddress());
        registerPage.emailInput.click();
        registerPage.emailInput.sendKeys(Page.getA18NProfile().getEmailAddress());
    }

    @And("she submits the registration form")
    public void sheSubmitsTheRegistrationForm() {
        registerPage.sleep();
        registerPage.signInButton.click();
    }

    @Then("she sees a list of required factors to setup")
    public void sheSeesAListOfRequiredFactorsToSetup() {
        registerPage.sleep();
        //Assert.assertTrue(registerPage.codeInput.isDisplayed());
    }

    @When("she selects Email")
    public void sheSelectsEmail() {
        registerPage.sleep();
        registerPage.emailRadioButton.click();
        registerPage.proceedButton.click();
    }

    @Then("she sees a page to input a code")
    public void sheSeesAPageToInputACode() {
        registerPage.sleep();
        Assert.assertTrue(registerPage.codeInput.isDisplayed());
    }

    @When("she inputs the correct code from her email")
    public void sheInputsTheCorrectCodeFromHerEmail() {
        A18NEmail email = null;
        String code;
        int retryCount = 5; //TODO Should be in config
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
        code = email.fetchCode();
        Assert.assertNotNull(code);
        registerPage.codeInput.click();
        registerPage.codeInput.sendKeys(code);
    }

    @And("she submits the verify form")
    public void sheSubmitsTheVerifyForm() {
        registerPage.verifyButton.click();
    }

    @When("she selects Password")
    public void sheSelectsPassword() {
        registerPage.sleep();
        registerPage.passwordRadioButton.click();
        registerPage.proceedButton.click();
    }

    @Then("she sees a page to setup password")
    public void sheSeesAPageToSetupPassword() {
        registerPage.sleep();
        Assert.assertTrue(registerPage.newPasswordInput.isDisplayed());
        Assert.assertTrue(registerPage.confirmNewPasswordInput.isDisplayed());
    }

    @When("she fills out her Password")
    public void sheFillsOutHerPassword() {
        registerPage.sleep();
        registerPage.newPasswordInput.click();
        registerPage.newPasswordInput.sendKeys("QwErTy@123");
    }

    @And("she confirms her Password")
    public void sheConfirmsHerPassword() {
        registerPage.confirmNewPasswordInput.click();
        registerPage.confirmNewPasswordInput.sendKeys("QwErTy@123");
    }

    @Then("she sees the list of optional factors")
    public void sheSeesTheListOfOptionalFactorsSMS() {
        registerPage.sleep();
    }

    @When("she selects \"Skip\" on SMS")
    public void sheSelectsOnSMS() {
        registerPage.sleep();
        registerPage.skipButton.click();
    }

    @And("an application session is created")
    public void anApplicationSessionIsCreated() {
        Assert.assertTrue(registerPage.profileTable.isDisplayed());
    }

}
