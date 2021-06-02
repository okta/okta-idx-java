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

import io.cucumber.spring.CucumberContextConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.test.context.SpringBootContextLoader;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ContextConfiguration;

@CucumberContextConfiguration
@ContextConfiguration(classes = TestApplication.class, loader = SpringBootContextLoader.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class CucumberRoot {

    private final Logger logger = LoggerFactory.getLogger(CucumberRoot.class);

    protected String USERNAME = System.getenv("USERNAME");
    protected String USERNAME_WITH_APP_UNASSIGNED = System.getenv("USERNAME_WITH_APP_UNASSIGNED");
    protected String USERNAME_SUSPENDED = System.getenv("USERNAME_SUSPENDED");
    protected String USERNAME_LOCKED = System.getenv("USERNAME_LOCKED");
    protected String USERNAME_DEACTIVATED = System.getenv("USERNAME_DEACTIVATED");
    protected String PASSWORD = System.getenv("PASSWORD");

    protected String USERNAME_FACEBOOK = System.getenv("USERNAME_FACEBOOK");
    protected String PASSWORD_FACEBOOK = System.getenv("PASSWORD_FACEBOOK");

    /**
     * Need this method so the cucumber will recognize this class as glue and load spring context configuration.
     */

}