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
import pages.LoginPage;
import pages.ProfilePage;
import pages.RootPage;

public class Login extends CucumberRoot {

    protected WebDriver driver = DriverUtil.getDefaultDriver();
    protected RootPage rootPage = new RootPage(driver);
    protected LoginPage loginPage = new LoginPage(driver);
    protected ProfilePage profilePage = new ProfilePage(driver);

    @Given("Mary navigates to the Embedded Widget View")
    public void maryNavigatesToTheEmbeddedWidgetView() {
        rootPage.navigateToTheRootPage();
        rootPage.waitForWebElementDisplayed(rootPage.loginButton);
        Assert.assertTrue(rootPage.loginButton.isDisplayed());
        rootPage.loginButton.click();
    }

    @When("she fills in her correct username")
    public void sheFillsInHerCorrectUsername() {
        loginPage.waitForWebElementDisplayed(loginPage.usernameInput);
        Assert.assertTrue(loginPage.usernameInput.isDisplayed());
        loginPage.usernameInput.click();
        loginPage.usernameInput.sendKeys(USERNAME);
    }

    @And("she fills in her correct password")
    public void sheFillsInHerCorrectPassword() {
        Assert.assertTrue(loginPage.passwordInput.isDisplayed());
        loginPage.passwordInput.click();
        loginPage.passwordInput.sendKeys(PASSWORD);
    }

    @And("she submits the Login form")
    public void sheSubmitsTheLoginForm() {
        Assert.assertTrue(loginPage.submitButton.isDisplayed());
        loginPage.submitButton.click();
    }

    @Then("she is redirected to the Root View")
    public void sheIsRedirectedToTheRootView() {
        rootPage.waitForWebElementDisplayed(rootPage.logoutButton);
        Assert.assertTrue(rootPage.logoutButton.isDisplayed());
        Assert.assertTrue(rootPage.profileLink.isDisplayed());
        rootPage.profileLink.click();
    }

    @And("she sees a table with her profile info")
    public void sheSeesATableWithHerProfileInfo() {
        profilePage.waitForWebElementDisplayed(profilePage.claimSubData);
        Assert.assertTrue(profilePage.claimSubData.isDisplayed());
    }

    @And("the cell for the value of \"email\" is shown and contains her email")
    public void theCellForTheValueOfIsShownAndContainsHerEmail() {
        profilePage.waitForWebElementDisplayed(profilePage.claimEmailData);
        Assert.assertTrue(profilePage.claimEmailData.isDisplayed());
        Assert.assertEquals(profilePage.claimEmailData.getText(), USERNAME);
    }
}
