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
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import org.junit.Assert;
import org.openqa.selenium.By;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;

public class Login extends BasicDefinitions {

	@Given("^Mary navigates to the login page$")
	public void navigate_to_home_page() {
		driver.manage().window().maximize();
		driver.get("http://localhost:8080");
		driver.findElement(By.id("login")).click();
	}

	@When("^she enters valid credentials$")
	public void enter_valid_credentials() {
		sleep();
		driver.findElement(By.name("username")).sendKeys("USERNAME");
		driver.findElement(By.name("password")).sendKeys("PASSWORD");
	}

	@And("^she submits the Login form$")
	public void clicks_login_button() {
		driver.findElement(By.id("sign-in-btn")).click();
	}
	
	@Then("^Mary should get logged-in$")
	public void should_logged_in() {
		By selection = By.id("profileTable");
        (new WebDriverWait(driver, 30)).until(
                ExpectedConditions.visibilityOfElementLocated(selection));
		String email = driver.findElement(By.id("email")).getText();
		Assert.assertTrue("Can't access profile information", email.contains(USERNAME));
	}

	@When("^she fills in her incorrect username with password$")
	public void enter_invalid_username() {
		sleep();
		driver.findElement(By.name("username")).sendKeys("invalid@acme.com");
		driver.findElement(By.name("password")).sendKeys(PASSWORD);
	}

	@Then("^she should see invalid user error$")
	public void invalid_user_error() {
		By selection = By.className("alert-danger");
		(new WebDriverWait(driver, 30)).until(
				ExpectedConditions.visibilityOfElementLocated(selection));
		String error = driver.findElement(By.className("alert-danger")).getText();
		Assert.assertTrue("Error is not shown", !error.isEmpty());
		// TODO - In some orgs, we also see "you don't have permissions" error. Check why the difference.
		// Assert.assertTrue("Invalid username error is not shown'", error.contains("There is no account with the Username"));
	}

	@When("^she fills in her correct username with incorrect password$")
	public void enter_valid_username_invalid_password() {
		sleep();
		driver.findElement(By.name("username")).sendKeys(USERNAME);
		driver.findElement(By.name("password")).sendKeys("invalid123");
	}

	@Then("^she should see authentication failed error$")
	public void authentication_failed_error() {
		By selection = By.className("alert-danger");
		(new WebDriverWait(driver, 30)).until(
				ExpectedConditions.visibilityOfElementLocated(selection));
		String error = driver.findElement(By.className("alert-danger")).getText();
		Assert.assertTrue("Error is not shown", !error.isEmpty());
		Assert.assertTrue("Authentication failed error is not shown'", error.contains("Authentication failed"));
	}

	@When("^she enters valid credentials for unassigned user$")
	public void enter_valid_credentials_for_unassigned_user() {
		sleep();
		driver.findElement(By.name("username")).sendKeys(USERNAME_WITH_APP_UNASSIGNED);
		driver.findElement(By.name("password")).sendKeys(PASSWORD);
	}

	@Then("^she should see user not assigned to app error$")
	public void user_not_assigned_app_error() {
		By selection = By.className("alert-danger");
		(new WebDriverWait(driver, 30)).until(
				ExpectedConditions.visibilityOfElementLocated(selection));
		String error = driver.findElement(By.className("alert-danger")).getText();
		Assert.assertTrue("Error is not shown", !error.isEmpty());
//		TODO: If Profile enrollment policy allows sign-up, this error in not shown. Commenting until we get clarity on this
//		Assert.assertTrue("User not assigned error is not shown", error.contains("User is not assigned to this application"));
	}

	@When("^she enters valid credentials for suspended user$")
	public void enter_valid_credentials_for_suspended_user() {
		sleep();
		driver.findElement(By.name("username")).sendKeys(USERNAME_SUSPENDED);
		driver.findElement(By.name("password")).sendKeys(PASSWORD);
	}

	@When("^she enters valid credentials for locked user$")
	public void enter_valid_credentials_for_locked_user() {
		sleep();
		driver.findElement(By.name("username")).sendKeys(USERNAME_LOCKED);
		driver.findElement(By.name("password")).sendKeys(PASSWORD);
	}

	@When("^she enters valid credentials for deactivated user$")
	public void enter_valid_credentials_for_deactivated_user() {
		sleep();
		driver.findElement(By.name("username")).sendKeys(USERNAME_DEACTIVATED);
		driver.findElement(By.name("password")).sendKeys(PASSWORD);
	}

	@When("^she clicks on the \"Forgot Password Link\"$")
	public void clicks_forgot_password_link() {
		sleep();
		By selection = By.id("forgot-password");
		(new WebDriverWait(driver, 30)).until(
				ExpectedConditions.visibilityOfElementLocated(selection));
		driver.findElement(By.id("forgot-password")).click();
	}

	@Then("^she is redirected to the Self Service Password Reset View$")
	public void redirect_to_sspr_view() {
		By selection = By.className("forgotpassword-form");
		(new WebDriverWait(driver, 30)).until(
				ExpectedConditions.visibilityOfElementLocated(selection));
		String URL = driver.getCurrentUrl();
		Assert.assertEquals(URL, "http://localhost:8080/forgot-password" );
	}

	@Then("^I close browser$")
	public void close_browser() {
		driver.close();
	}
}
