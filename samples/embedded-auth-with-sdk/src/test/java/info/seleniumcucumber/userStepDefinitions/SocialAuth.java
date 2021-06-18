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
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import org.junit.Assert;
import org.openqa.selenium.WebDriver;
import pages.FacebookLoginPage;
import pages.GoogleLoginPage;
import pages.LoginPage;
import pages.RootPage;

public class SocialAuth extends CucumberRoot {

    protected WebDriver driver = DriverUtil.getDefaultDriver();
    private RootPage rootPage = new RootPage(driver);
    private LoginPage loginPage = new LoginPage(driver);
    private FacebookLoginPage facebookLoginPage = new FacebookLoginPage(driver);
    private GoogleLoginPage googleLoginPage = new GoogleLoginPage(driver);

    @Given("^she clicks the \"Login with Facebook\" button$")
    public void clicks_facebook_login() {
        Assert.assertTrue(loginPage.facebookLoginButton.isDisplayed());
        loginPage.facebookLoginButton.click();
    }

    @And("logs in to Facebook with {word} and {word}")
    public void logs_in_to_facebook(String email, String password) {
        Assert.assertTrue(facebookLoginPage.emailInput.isDisplayed());
        facebookLoginPage.emailInput.click();
        facebookLoginPage.emailInput.sendKeys(System.getenv(email));

        Assert.assertTrue(facebookLoginPage.passwordInput.isDisplayed());
        facebookLoginPage.passwordInput.click();
        facebookLoginPage.passwordInput.sendKeys(System.getenv(password));

        Assert.assertTrue(facebookLoginPage.loginButton.isDisplayed());
        facebookLoginPage.loginButton.click();
    }

    @Given("^she clicks the \"Login with Google\" button in the embedded Sign In Widget$")
    public void clicks_google_login() {
        Assert.assertTrue(loginPage.googleLoginButton.isDisplayed());
        loginPage.googleLoginButton.click();
    }

    @And("logs in to Google with {word} and {word}")
    public void logs_in_to_google(String email, String password) {
        Assert.assertTrue(googleLoginPage.emailInput.isDisplayed());
        googleLoginPage.emailInput.click();
        googleLoginPage.emailInput.sendKeys(System.getenv(email));
        googleLoginPage.submit(googleLoginPage.emailInput);

        googleLoginPage.waitForWebElementDisplayed(googleLoginPage.passwordInput);
        Assert.assertTrue(googleLoginPage.passwordInput.isDisplayed());
        googleLoginPage.passwordInput.click();
        googleLoginPage.passwordInput.sendKeys(System.getenv(password));
        googleLoginPage.submit(googleLoginPage.passwordInput);
    }

    @Then("^the Root Page shows links to the Entry Points$")
    public void the_root_page_shows_links_to_the_entry_points() {
        Assert.assertTrue(rootPage.loginButton.isDisplayed());
        Assert.assertTrue(rootPage.registrationButton.isDisplayed());
    }

    @Given("^Mary navigates to root page$")
    public void mary_navigates_to_root_page() {
        rootPage.navigateToTheRootPage();
    }

    @And("^the remediation returns \"MFA_REQUIRED\"$")
    public void the_remediation_returns_mfa_required(){
        rootPage.waitForWebElementDisplayed(rootPage.alertDanger);
        Assert.assertTrue(rootPage.getCurrentUrl().contains("error=interaction_required"));
    }

    @Then("^Mary should see an interaction_required error message$")
    public void mary_should_see_an_error_message(){
        Assert.assertTrue(rootPage.alertDanger.isDisplayed());
        Assert.assertEquals("Your client is configured to use the interaction code flow and user interaction is required to complete the request.", rootPage.alertDanger.getText());
    }
}
