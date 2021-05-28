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
import cucumber.api.java.en.Then;
import env.CucumberRoot;
import env.DriverUtil;
import org.junit.Assert;
import org.openqa.selenium.WebDriver;
import pages.RootPage;

public class CommonSteps extends CucumberRoot {

    protected WebDriver driver = DriverUtil.getDefaultDriver();
    private RootPage rootPage = new RootPage(driver);

    @Given("^Mary navigates to the Basic Login View$")
    public void navigate_to_basic_login_view() {
        rootPage.navigateToTheRootPage();
        Assert.assertTrue(rootPage.loginButton.isDisplayed());
        rootPage.loginButton.click();
    }

    @Given("^Mary navigates to the Self Service Registration View$")
    public void maryNavigatesToTheSelfServiceRegistrationView() {
        rootPage.navigateToTheRootPage();
        if(rootPage.isRegistrationButtonDisplayed()) {
            rootPage.registrationButton.click();
        }
    }

    @Then("^I close browser$")
    public void close_browser() {
        driver.close();
    }
}
