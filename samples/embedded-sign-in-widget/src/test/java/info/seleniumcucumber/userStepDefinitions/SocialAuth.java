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
import org.junit.Assert;
import org.openqa.selenium.WebDriver;
import pages.FacebookLoginPage;
import pages.LoginPage;

public class SocialAuth extends CucumberRoot {

    protected WebDriver driver = DriverUtil.getDefaultDriver();
    private LoginPage loginPage = new LoginPage(driver);
    private FacebookLoginPage facebookLoginPage = new FacebookLoginPage(driver);

    @Given("^she clicks the \"Login with Facebook\" button$")
    public void clicks_facebook_login() {
        loginPage.waitForWebElementDisplayed(loginPage.facebookLoginButton);
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
}
