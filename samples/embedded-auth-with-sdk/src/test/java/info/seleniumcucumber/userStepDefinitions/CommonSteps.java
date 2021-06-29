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
import io.cucumber.java.en.When;
import org.junit.Assert;
import org.openqa.selenium.WebDriver;
import pages.RootPage;

public class CommonSteps extends CucumberRoot {

    protected WebDriver driver = DriverUtil.getDefaultDriver();
    private RootPage rootPage = new RootPage(driver);

    @Given("^Mary navigates to the Basic Login View$")
    public void navigate_to_basic_login_view() {
        rootPage.navigateToTheRootPage();
        rootPage.waitForWebElementDisplayed(rootPage.loginButton);
        Assert.assertTrue(rootPage.loginButton.isDisplayed());
        rootPage.loginButton.click();
    }

    @Given("^Mary navigates to the Self Service Registration View$")
    public void mary_navigates_to_the_self_service_registration_view() {
        rootPage.navigateToTheRootPage();
        rootPage.waitForWebElementDisplayed(rootPage.registrationButton);
        if(rootPage.registrationButton.isDisplayed()) {
            rootPage.registrationButton.click();
        }
    }

    @Given("^Mary navigates to the Self Service Password Reset View$")
    public void mary_navigates_to_the_self_service_password_reset_view() {
        rootPage.navigateToThePasswordResetPage();
    }

    @When("Mary clicks the logout button")
    public void mary_clicks_the_logout_button() {
        rootPage.logoutButton.click();
    }

    @And("Mary sees login, registration buttons")
    public void mary_sees_login_registration_buttons() {
        Assert.assertTrue(rootPage.registrationButton.isDisplayed());
        Assert.assertTrue(rootPage.loginButton.isDisplayed());

    }

    @And("she does not see claims from \\/userinfo")
    public void she_does_not_see_claims_from_userinfo() {
        Assert.assertFalse(rootPage.elementIsDisplayed(rootPage.refreshToken));
        Assert.assertFalse(rootPage.elementIsDisplayed(rootPage.accessToken));
        Assert.assertFalse(rootPage.elementIsDisplayed(rootPage.profileTable));
    }
}
