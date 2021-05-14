package env;

import cucumber.api.java.After;
import cucumber.api.java.Before;
import org.openqa.selenium.By;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;

import java.io.IOException;

public class Hooks {
	protected WebDriver driver = DriverUtil.getDefaultDriver();

	@Before
	public void beforeScenario(){
		System.out.println("This will run before the Scenario");
	}

	@After
	public void afterScenario(){
		System.out.println("This will run after the Scenario");

		if (isAlive() && existsElement("logout-btn")) {
			System.out.println("Found the logout button. Clicking it...");
			driver.findElement(By.id("logout-btn")).click();
		}
	}

	private boolean existsElement(String id) {
		try {
			driver.findElement(By.id(id));
		} catch (NoSuchElementException e) {
			return false;
		}
		return true;
	}

	/**
	 *
	 * @return true if driver is alive else false
	 */
	public Boolean isAlive() {
		try {
			driver.getCurrentUrl();//or driver.getTitle();
			return true;
		} catch (Exception ex) {
			return false;
		}
	}
}
