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
import io.cucumber.java.en.Given;
import env.CucumberRoot;
import env.DriverUtil;
import org.junit.Assert;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;
import pages.FacebookLoginPage;
import pages.LoginPage;
import pages.RootPage;

public class SocialAuth extends CucumberRoot {

    protected WebDriver driver = DriverUtil.getDefaultDriver();
    private RootPage rootPage = new RootPage(driver);
//    private FacebookLoginPage facebookLoginPage = new FacebookLoginPage(driver);

//    @Given("^she clicks the \"Login with Facebook\" button$")
//    public void clicks_facebook_login() {
//        loginPage.sleep();
//        Assert.assertTrue(loginPage.facebookLoginButton.isDisplayed());
//        loginPage.facebookLoginButton.click();
//    }
//
//    @And("^logs in to Facebook$")
//    public void login_facebook() {
//        facebookLoginPage.sleep();
//
//        Assert.assertTrue(facebookLoginPage.emailInput.isDisplayed());
//        facebookLoginPage.emailInput.click();
//        facebookLoginPage.emailInput.sendKeys(USERNAME_FACEBOOK);
//
//        Assert.assertTrue(facebookLoginPage.passwordInput.isDisplayed());
//        facebookLoginPage.passwordInput.click();
//        facebookLoginPage.passwordInput.sendKeys(PASSWORD_FACEBOOK);
//
//        Assert.assertTrue(facebookLoginPage.loginButton.isDisplayed());
//        facebookLoginPage.loginButton.click();
//    }

    @Then("^the Root Page shows links to the Entry Points$")
    public void the_root_page_shows_links_to_the_entry_points() {
        Assert.assertTrue(rootPage.loginButton.isDisplayed());
        Assert.assertTrue(rootPage.registrationButton.isDisplayed());
    }

    @Given("^Mary navigates to root page$")
    public void mary_navigates_to_root_page() {
        rootPage.navigateToTheRootPage();
    }
}
