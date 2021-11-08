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
import org.openqa.selenium.WebDriver;
import pages.SelectAuthenticatorPage;

public class WebAuthnSupport extends CucumberRoot {

    protected WebDriver driver = DriverUtil.getDefaultDriver();
    private SelectAuthenticatorPage selectAuthenticatorPage = new SelectAuthenticatorPage(driver);

    @When("^she selects Biometric from the list$")
    public void she_selects_biometric_from_the_list() {
        selectAuthenticatorPage.wedAuthnButton.click();
    }

    @And("^she selects \"Set up\"$")
    public void she_selects_set_up() {
        selectAuthenticatorPage.proceedButton.click();
    }

    @Then("^she sees a prompt to select a Security Key or This Device$")
    public void she_sees_a_prompt_to_select_a_security_key_or_this_device() {
        System.out.println();
        System.out.println();
    }

}
