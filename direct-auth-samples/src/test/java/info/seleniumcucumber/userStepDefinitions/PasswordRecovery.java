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
import env.a18n.client.response.A18NEmail;
import io.cucumber.java.en.And;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import org.junit.Assert;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import pages.*;

public class PasswordRecovery extends CucumberRoot {

	private static final int RETRY_COUNT = 5; //TODO Should be in config
	private static final String EXAMPLE_EMAIL = "mary@unknown.com";

	protected WebDriver driver = DriverUtil.getDefaultDriver();
	protected PasswordRecoveryPage passwordRecoveryPage = new PasswordRecoveryPage(driver);
	protected SelectAuthenticatorPage selectAuthenticatorPage = new SelectAuthenticatorPage(driver);
	protected RegisterPage registerPage = new RegisterPage(driver);

	@When("^she inputs her correct Email$")
	public void she_inputs_her_correct_email() {
		Assert.assertNotNull(Page.getA18NProfile());
		Assert.assertNotNull(Page.getA18NProfile().getEmailAddress());
		Assert.assertNotNull(Page.getUser());
		Assert.assertTrue(passwordRecoveryPage.usernameInput.isDisplayed());
		passwordRecoveryPage.usernameInput.click();
		passwordRecoveryPage.usernameInput.sendKeys(Page.getUser().getProfile().getEmail());
	}

	@And("^she submits the recovery form$")
	public void she_submits_the_recovery_form() {
		passwordRecoveryPage.nextButton.click();
	}

	@Then("^she sees the list of authenticators$")
	public void she_sees_the_list_of_authenticators() {
	 	Assert.assertTrue(passwordRecoveryPage.emailRadioButton.isDisplayed());
	}

	@When("^she selects Email authenticator$")
	public void she_selects_email_authenticator() {
		passwordRecoveryPage.emailRadioButton.click();
		passwordRecoveryPage.proceedButton.click();
	}

	@Then("^she sees a page to input her code$")
	public void she_sees_a_page_to_input_her_code() {
		Assert.assertTrue(selectAuthenticatorPage.codeInput.isDisplayed());
	}

	@When("^she fills in the correct code$")
	public void she_fills_in_the_correct_code() {
		A18NEmail email = null;
		String code;
		int retryCount = RETRY_COUNT;
		while(retryCount > 0) {
			selectAuthenticatorPage.sleep();
			email = Page.getA18NClient().getLatestEmail(Page.getA18NProfile());
			if(email != null && email.getContent() != null) {
				break;
			} else {
				retryCount--;
			}
		}
		Assert.assertNotNull(email);
		code = email.fetchCodeFromPasswordResetEmail();
		Assert.assertNotNull(code);
		selectAuthenticatorPage.codeInput.click();
		selectAuthenticatorPage.codeInput.sendKeys(code);
	}

	@And("^she submits the form$")
	public void she_submits_the_form() {
		selectAuthenticatorPage.verifyButton.click();
	}

	@Then("^she sees a page to set her password$")
	public void she_sees_a_page_to_set_her_password() {
		Assert.assertTrue(registerPage.newPasswordInput.isDisplayed());
	}

	@When("^she fills a password that fits within the password policy$")
	public void she_fills_a_password_that_fits_within_the_password_policy() {
		registerPage.newPasswordInput.click();
		registerPage.newPasswordInput.sendKeys("QwErTy@123");
	}

	@And("^she confirms that password$")
	public void she_confirms_that_password() {
		registerPage.confirmNewPasswordInput.click();
		registerPage.confirmNewPasswordInput.sendKeys("QwErTy@123");
	}

	@When("she selects \"Forgot Password\"")
	public void she_selects_forgot_password() {
		driver.findElement(By.id("forgot-password")).click();
	}

	@Then("she sees the Password Recovery Page")
	public void she_sees_the_password_recovery_page() {
		Assert.assertTrue("URL should ends with \"/forgot-password\"", driver.getCurrentUrl().endsWith("/forgot-password"));
		Assert.assertEquals("Wrong page title", "Forgot Password", driver.getTitle());
		Assert.assertTrue(driver.findElement(By.className("forgotpassword-form")).isDisplayed());
	}

	@When("she inputs an Email that doesn't exist")
	public void she_inputs_an_email_that_doesnt_exist() {
		driver.findElement(By.name("username")).sendKeys(EXAMPLE_EMAIL);
	}

	@Then("she sees a message \"There is no account with the Username mary@unknown.com.\"")
	public void she_sees_a_message() {
		WebElement alert = driver.findElement(By.className("alert-danger"));
		Assert.assertTrue(alert.isDisplayed());
		String errorMsg = alert.getText();
		Assert.assertFalse("Error is not shown", errorMsg.isEmpty());
		Assert.assertEquals("Wrong error message is shown", "[There is no account with the Username " + EXAMPLE_EMAIL + ".]", errorMsg);
	}
}
