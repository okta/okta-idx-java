package pages;

import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.FindBy;
import org.openqa.selenium.support.PageFactory;

public class RootPage {
    protected WebDriver driver;

    public RootPage(WebDriver driver){
        this.driver = driver;
        PageFactory.initElements(driver, this);
    }

    @FindBy(id = "login")
    public WebElement loginButton;

    @FindBy(id = "register")
    public WebElement registrationButton;

    public void navigateToTheRootPage(){
        driver.manage().window().maximize();
        driver.get("http://localhost:8080"); // TODO pass as env variable.
    }

    public boolean isLoginButtonDisplayed(){
        return loginButton.isDisplayed();
    }

    public boolean isRegistrationButtonDisplayed(){
        return registrationButton.isDisplayed();
    }
}
