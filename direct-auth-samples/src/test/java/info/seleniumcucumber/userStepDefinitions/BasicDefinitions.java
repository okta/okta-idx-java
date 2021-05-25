package info.seleniumcucumber.userStepDefinitions;

import env.CucumberRoot;
import env.DriverUtil;
import org.openqa.selenium.WebDriver;

public class BasicDefinitions {

    protected WebDriver driver = DriverUtil.getDefaultDriver();
    protected String USERNAME = System.getenv("USERNAME");
    protected String USERNAME_WITH_APP_UNASSIGNED = System.getenv("USERNAME_WITH_APP_UNASSIGNED");
    protected String USERNAME_SUSPENDED = System.getenv("USERNAME_SUSPENDED");
    protected String USERNAME_LOCKED = System.getenv("USERNAME_LOCKED");
    protected String USERNAME_DEACTIVATED = System.getenv("USERNAME_DEACTIVATED");
    protected String PASSWORD = System.getenv("PASSWORD");

    protected void sleep() {
        try {
            Thread.sleep(500);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }
}
