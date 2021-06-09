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

import io.cucumber.java.After;
import io.cucumber.java.Before;
import org.openqa.selenium.By;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.WebDriver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Hooks {

	private final Logger logger = LoggerFactory.getLogger(Hooks.class);

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
