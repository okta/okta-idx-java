package info.seleniumcucumber.userStepDefintions;
import org.junit.Assert;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;

import cucumber.api.java.en.Given;
import env.DriverUtil;
//import info.seleniumcucumber.methods.BaseTest;


public class UserStepDefinitions {
	
	protected WebDriver driver = DriverUtil.getDefaultDriver();
	
	@Given("^I should get logged-in$")
	public void should_logged_in() throws Throwable {
		
		By selection = By.className("alert");
        (new WebDriverWait(driver, 30)).until(
                ExpectedConditions.visibilityOfElementLocated(selection));
		String msg = driver.findElement(By.className("alert")).getText();
		if(!msg.isEmpty())
			msg = msg.split("\n")[0].trim();
		Assert.assertTrue("Logged in successfully", msg.contains("Welcome"));
	}
}
