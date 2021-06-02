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
package env;


import env.a18n.client.DefaultA18NClientBuilder;
import io.cucumber.java.After;
import io.cucumber.java.Before;
import io.cucumber.java.Scenario;
import org.openqa.selenium.By;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.WebDriver;
import pages.Page;

public class Hooks {
	protected WebDriver driver = DriverUtil.getDefaultDriver();

	@Before
	public void beforeScenario(){
		System.out.println("This will run before each Scenario");
	}

	@After
	public void afterScenario(){
		System.out.println("This will run after each Scenario");

		if (isAlive() && existsElement("logout-btn")) {
			driver.findElement(By.id("logout-btn")).click();
		}
		DriverUtil.closeDriver();
	}

	@Before("@requireA18NProfile")
	public void createA18NProfileBeforeScenario(Scenario scenario) {
		if(Page.getA18NClient() == null) {
			Page.setA18NClient(new DefaultA18NClientBuilder().build());
		}
		if(Page.getA18NProfile() == null) {
			Page.setA18NProfile(Page.getA18NClient().createProfile());
		}
	}

	@After("@requireA18NProfile")
	public void removeA18NProfileAfterScenario(Scenario scenario) {
		if(Page.getA18NProfile() != null && Page.getA18NClient() != null) {
			Page.getA18NClient().deleteProfile(Page.getA18NProfile());
			Page.setA18NProfile(null);
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
