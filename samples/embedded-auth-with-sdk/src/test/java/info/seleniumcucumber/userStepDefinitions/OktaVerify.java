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

import com.okta.sdk.client.Client;
import com.okta.sdk.client.ClientBuilder;
import com.okta.sdk.client.Clients;
import com.okta.sdk.resource.user.User;
import com.okta.sdk.resource.user.UserBuilder;
import env.CucumberRoot;
import env.DriverUtil;
import io.cucumber.java.en.And;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import org.apache.commons.lang3.StringUtils;
import org.junit.Assert;
import org.openqa.selenium.WebDriver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pages.*;

public class OktaVerify extends CucumberRoot {

	protected WebDriver driver = DriverUtil.getDefaultDriver();

	public RegisterPage registerPage = new RegisterPage(driver);
	public RegisterPhonePage registerPhonePage = new RegisterPhonePage(driver);
	public SelectAuthenticatorPage selectAuthenticatorPage = new SelectAuthenticatorPage(driver);
	public VerifyPage verifyPage = new VerifyPage(driver);
	public OktaVerifyPage oktaVerifyPage = new OktaVerifyPage(driver);

	public ClientBuilder builder = Clients.builder();
	public Client client = builder.build();

	private final Logger logger = LoggerFactory.getLogger(OktaVerify.class);


	@When("^she selects okta verify from the list$")
	public void she_selects_okta_verify_from_the_list() {
		oktaVerifyPage.oktaVerifyRadioButton.click();
		selectAuthenticatorPage.proceedButton.click();
	}


	@And("^she sees the option \"Can't scan?\"$")
	public void she_sees_the_option_cant_scan() {
		oktaVerifyPage.waitForWebElementDisplayed(oktaVerifyPage.optionsLink);
		Assert.assertTrue(oktaVerifyPage.optionsLink.isDisplayed());
	}

	@And("^she clicks on \"Can't scan?\"$")
	public void she_clicks_on_cant_scan() {
		oktaVerifyPage.optionsLink.click();
	}

	@Then("^she sees a page to input the phone number$")
	public void she_sees_a_page_to_input_the_phone_number() {
		oktaVerifyPage.waitForWebElementDisplayed(oktaVerifyPage.phoneOrEmailTextBox);
		Assert.assertTrue(oktaVerifyPage.phoneOrEmailTextBox.isDisplayed());
	}

	@And("^she clicks on submit button saying \"Send me the setup link\"$")
	public void she_clicks_on_submit_button_saying_send_me_the_setup_link() {
		oktaVerifyPage.waitForWebElementDisplayed(registerPage.verifyButton);
		registerPage.verifyButton.click();
	}

	@And("^the screen changes to a waiting screen saying \"We sent an SMS with an Okta Verify setup link. To continue, open the link on your mobile device.\"$")
	public void the_screen_changes_to_waiting_screen_for_sms() {
		Assert.assertTrue(oktaVerifyPage.waitingScreen.isDisplayed());
	}

	@And("^the screen changes to a waiting screen saying \"We sent an email with an Okta Verify setup link. To continue, open the link on your mobile device.\"$")
	public void the_screen_changes_to_waiting_screen_for_email() {
		Assert.assertTrue(oktaVerifyPage.waitingScreen.isDisplayed());
	}

	@Then("^she sees a page to input the Email$")
	public void she_sees_a_page_to_input_the_email() {
		oktaVerifyPage.waitForWebElementDisplayed(oktaVerifyPage.phoneOrEmailTextBox);
		Assert.assertTrue(oktaVerifyPage.phoneOrEmailTextBox.isDisplayed());
	}

	@And("^she fills out her Email for Okta verify$")
	public void she_fills_out_her_email_for_okta_verify() {
		Assert.assertNotNull(Page.getA18NProfile());
		Assert.assertNotNull(Page.getA18NProfile().getEmailAddress());
		oktaVerifyPage.phoneOrEmailTextBox.click();
		oktaVerifyPage.phoneOrEmailTextBox.sendKeys(Page.getA18NProfile().getEmailAddress());
	}

	@And("^she inputs a valid phone number for Okta verify$")
	public void she_inputs_a_valid_phone_number_for_okta_verify() {
		Assert.assertNotNull(Page.getA18NProfile());
		Assert.assertNotNull(Page.getA18NProfile().getPhoneNumber());
		oktaVerifyPage.phoneOrEmailTextBox.click();
		oktaVerifyPage.phoneOrEmailTextBox.sendKeys(Page.getA18NProfile().getPhoneNumber());
	}


	@When("^she selects Email option$")
	public void she_selects_email_option() {
		oktaVerifyPage.waitForWebElementDisplayed(oktaVerifyPage.emailModeRadioButton);
		oktaVerifyPage.emailModeRadioButton.click();
		selectAuthenticatorPage.submitButton.click();
	}
	@When("^she selects SMS option$")
	public void she_selects_sms_option() {
		oktaVerifyPage.waitForWebElementDisplayed(oktaVerifyPage.smsModeRadioButton);
		oktaVerifyPage.smsModeRadioButton.click();
		selectAuthenticatorPage.submitButton.click();
	}

	@When("^she clicks on the link in her email$")
	public void she_clicks_on_the_link_in_her_email() {
		String emailContent = selectAuthenticatorPage.fetchEmailContent();
		Assert.assertNotNull(emailContent);
		String activationLink = selectAuthenticatorPage.fetchActivationLinkFromEmail(emailContent);
		Assert.assertNotNull(activationLink);
		driver.manage().window().maximize();
		driver.get(activationLink);
	}

	@When("^she clicks the link in her text messages from her phone$")
	public void she_clicks_the_link_in_her_text_messages_from_her_phone() {
		String activationLink = selectAuthenticatorPage.fetchLinkFromSMS();
		Assert.assertNotNull(activationLink);
		driver.manage().window().maximize();
		driver.get(activationLink);
	}

	@Then("^she sees the download okta verify screen$")
	public void she_sees_the_download_okta_verify_screen() {
		oktaVerifyPage.waitForWebElementDisplayed(oktaVerifyPage.oktaVerifyScreen);
		Assert.assertTrue(oktaVerifyPage.oktaVerifyScreen.isDisplayed());
	}


	@Then("^she sees a list of modes to register$")
	public void she_sees_a_list_of_modes_to_register() {
		oktaVerifyPage.waitForWebElementDisplayed(oktaVerifyPage.authenticatorsOption);
		Assert.assertTrue(oktaVerifyPage.authenticatorsOption.isDisplayed());
	}

	@Then("^she sees a page with QR code displayed for scanning$")
	public void she_sees_a_page_with_qr_code_displayed_for_scanning() {
		oktaVerifyPage.waitForWebElementDisplayed(oktaVerifyPage.qrCodeDisplayed);
		Assert.assertTrue(oktaVerifyPage.qrCodeDisplayed.isDisplayed());
	}

	@Then("^she is presented with an option to select Okta Verify$")
	public void she_is_presented_with_an_option_to_select_okta_verify() {
		Assert.assertTrue(selectAuthenticatorPage.selectAuthenticatorsForm.isDisplayed());
		Assert.assertTrue(oktaVerifyPage.oktaVerifyOption.isDisplayed());

	}

	@When("^she selects okta verify$")
	public void she_selects_okta_verify() {
		oktaVerifyPage.oktaVerifyOption.click();
		selectAuthenticatorPage.proceedButton.click();
	}
}
