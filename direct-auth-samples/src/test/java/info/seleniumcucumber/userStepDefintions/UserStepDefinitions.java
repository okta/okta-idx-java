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
package info.seleniumcucumber.userStepDefintions;

import cucumber.api.java.en.And;
import cucumber.api.java.en.Given;
import cucumber.api.java.en.Then;
import cucumber.api.java.en.When;
import env.CucumberRoot;
import env.DriverUtil;
import org.junit.Assert;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;

public class UserStepDefinitions extends CucumberRoot {
	
	protected WebDriver driver = DriverUtil.getDefaultDriver();
	private String USERNAME = System.getenv("USERNAME");
	private String USERNAME_WITH_APP_UNASSIGNED = System.getenv("USERNAME_WITH_APP_UNASSIGNED");
	private String USERNAME_SUSPENDED = System.getenv("USERNAME_SUSPENDED");
	private String USERNAME_LOCKED = System.getenv("USERNAME_LOCKED");
	private String USERNAME_DEACTIVATED = System.getenv("USERNAME_DEACTIVATED");
	private String PASSWORD = System.getenv("PASSWORD");

	@Given("^Mary navigates to the Basic Login View$")
	public void navigate_to_basic_login_view() {
		driver.manage().window().maximize();
		driver.get("http://localhost:8080");
		driver.findElement(By.id("login")).click();
	}

	@When("^she fills in her correct username$")
	public void enter_correct_username() throws Throwable {
		Thread.sleep(500); // Removing this fails the test. ¯\_(ツ)_/¯
		// The below block doesn't help either. Only sleep works. (╯°□°）╯︵ ┻━┻
		// new WebDriverWait(driver, 10).until(ExpectedConditions.elementToBeClickable(By.name("username"))).click();
		driver.findElement(By.name("username")).sendKeys(USERNAME);
	}

	@And("^she fills in her correct password$")
	public void enter_correct_password() throws Throwable {
		driver.findElement(By.name("password")).sendKeys(PASSWORD);
	}

	@And("^she submits the Login form$")
	public void clicks_login_button() {
		driver.findElement(By.id("sign-in-btn")).click();
	}

	@Then("^she is redirected to the Root View$")
	public void redirected_to_root_view() throws Throwable {
		By selection = By.id("profileTable");
		(new WebDriverWait(driver, 30)).until(
				ExpectedConditions.visibilityOfElementLocated(selection));
		String email = driver.findElement(By.id("email")).getText();
		Assert.assertTrue("Can't access profile information", email.contains(USERNAME));
	}

	@And("^the access_token is stored in session$")
	public void access_token_stored() throws Throwable {
		By selection = By.id("accessToken");
		(new WebDriverWait(driver, 30)).until(
				ExpectedConditions.visibilityOfElementLocated(selection));
		String accessToken = driver.findElement(By.id("accessToken")).getText();
		Assert.assertTrue("Can't access access_token", !accessToken.isEmpty());
	}

	@And("^the id_token is stored in session$")
	public void id_token_stored() throws Throwable {
		By selection = By.id("idToken");
		(new WebDriverWait(driver, 30)).until(
				ExpectedConditions.visibilityOfElementLocated(selection));
		String idToken = driver.findElement(By.id("idToken")).getText();
		Assert.assertTrue("Can't access id_token", !idToken.isEmpty());
	}

	@And("^the refresh_token is stored in session$")
	public void refresh_token_stored() throws Throwable {
		By selection = By.id("refreshToken");
		(new WebDriverWait(driver, 30)).until(
				ExpectedConditions.visibilityOfElementLocated(selection));
		String refreshToken = driver.findElement(By.id("refreshToken")).getText();
		Assert.assertTrue("Can't access refresh_token", !refreshToken.isEmpty());
	}

	@When("^she fills in her incorrect username$")
	public void enter_incorrect_username() throws Throwable {
		Thread.sleep(500); // Removing this fails the test. ¯\_(ツ)_/¯
		driver.findElement(By.name("username")).sendKeys("invalid@acme.com");
	}

	@Then("^she should see a \"There is no account with username\" message on the Login form$")
	public void no_account_user_error() {
		By selection = By.className("alert-danger");
		(new WebDriverWait(driver, 30)).until(
				ExpectedConditions.visibilityOfElementLocated(selection));
		String error = driver.findElement(By.className("alert-danger")).getText();
		Assert.assertTrue("Error is not shown", !error.isEmpty());
		// If sign-up is enabled for the app, we see the account doesn't exist error
		 Assert.assertTrue("No account with username error is not shown'", error.contains("There is no account with the Username"));
	}

	@When("^she fills in her incorrect password$")
	public void enter_incorrect_password() throws Throwable {
		driver.findElement(By.name("password")).sendKeys("invalid123");
	}

	@Then("^she should see the message \"Authentication failed\"$")
	public void authentication_failed_message() throws Throwable {
		By selection = By.className("alert-danger");
		(new WebDriverWait(driver, 30)).until(
				ExpectedConditions.visibilityOfElementLocated(selection));
		String error = driver.findElement(By.className("alert-danger")).getText();
		Assert.assertTrue("Error is not shown", !error.isEmpty());
		Assert.assertTrue("Authentication failed error is not shown'", error.contains("Authentication failed"));
	}

	@When("^she enters valid credentials for unassigned user$")
	public void enter_valid_credentials_for_unassigned_user() throws Throwable {
		Thread.sleep(500); // Removing this fails the test. ¯\_(ツ)_/¯
		driver.findElement(By.name("username")).sendKeys(USERNAME_WITH_APP_UNASSIGNED);
		driver.findElement(By.name("password")).sendKeys(PASSWORD);
	}

	@Then("^she should see user not assigned to app error$")
	public void user_not_assigned_app_error() throws Throwable {
		By selection = By.className("alert-danger");
		(new WebDriverWait(driver, 30)).until(
				ExpectedConditions.visibilityOfElementLocated(selection));
		String error = driver.findElement(By.className("alert-danger")).getText();
		Assert.assertTrue("Error is not shown", !error.isEmpty());
//		TODO: If Profile enrollment policy allows sign-up, this error in not shown. Commenting until we get clarity on this
//		Assert.assertTrue("User not assigned error is not shown", error.contains("User is not assigned to this application"));
	}

	@Given("^Mary's account is suspended$")
	public void suspended_user() throws Throwable {
		// This is a suspended user
		System.out.println(USERNAME_SUSPENDED);
	}

	@When("^she fills in her suspended username$")
	public void enter_suspended_username() throws Throwable {
		Thread.sleep(500); // Removing this fails the test. ¯\_(ツ)_/¯
		// The below block doesn't help either. Only sleep works. (╯°□°）╯︵ ┻━┻
		// new WebDriverWait(driver, 10).until(ExpectedConditions.elementToBeClickable(By.name("username"))).click();
		driver.findElement(By.name("username")).sendKeys(USERNAME_SUSPENDED);
	}

	@Given("^Mary's account is locked")
	public void locked_user() throws Throwable {
		// This is a suspended user
		System.out.println(USERNAME_LOCKED);
	}

	@When("^she fills in her locked username$")
	public void enter_locked_username() throws Throwable {
		Thread.sleep(500); // Removing this fails the test. ¯\_(ツ)_/¯
		// The below block doesn't help either. Only sleep works. (╯°□°）╯︵ ┻━┻
		// new WebDriverWait(driver, 10).until(ExpectedConditions.elementToBeClickable(By.name("username"))).click();
		driver.findElement(By.name("username")).sendKeys(USERNAME_LOCKED);
	}

	@Given("^Mary's account is deactivated")
	public void deactivated_user() throws Throwable {
		// This is a suspended user
		System.out.println(USERNAME_DEACTIVATED);
	}

	@When("^she fills in her deactivated username$")
	public void enter_deactivated_username() throws Throwable {
		Thread.sleep(500); // Removing this fails the test. ¯\_(ツ)_/¯
		// The below block doesn't help either. Only sleep works. (╯°□°）╯︵ ┻━┻
		// new WebDriverWait(driver, 10).until(ExpectedConditions.elementToBeClickable(By.name("username"))).click();
		driver.findElement(By.name("username")).sendKeys(USERNAME_DEACTIVATED);
	}

	@When("^she clicks on the \"Forgot Password Link\"$")
	public void clicks_forgot_password_link() throws Throwable {
		By selection = By.id("forgot-password");
		(new WebDriverWait(driver, 30)).until(
				ExpectedConditions.visibilityOfElementLocated(selection));
		driver.findElement(By.id("forgot-password")).click();
	}

	@Then("^she is redirected to the Self Service Password Reset View$")
	public void redirect_to_sspr_view() throws Throwable {
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
