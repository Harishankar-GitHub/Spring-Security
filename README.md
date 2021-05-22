# Spring Security

- Bootstrapped the application using [**start.spring.io**](https://start.spring.io/) 
- Created an **API**
- Added **Spring Security Dependency**
	- After adding the Spring Security Dependency, when the application is started and hit one of the APIs, the application redirects to the [login](http://localhost:8080/login) page.
	- The default username is ***user***
	- The default ***password*** is ***generated*** in the application console during the startup of the application.
	- [Logout](http://localhost:8080/logout) page is available as well.
	- This is known as **Form Based Authentication**.
- **Basic Authentication**
	- Authorization: **Base64** Username and Password
	- **HTTPS** Recommended
	- **Simple** and **Fast**
	- **Can't Logout**
- Implemented **Basic Authentication**
	- Added the configuration in *SecurityConfig.java* file.
	- After this, when the application starts, instead of Form Based Authentication, a pop up window appears and it prompts to enter the Username and Password.
	- This is known as **Basic Auth** from a Web Browser.
	- There's *NO LOGOUT PAGE*! The Username and Password is sent on every single request.
	- Hitting the API from Postman.
		- Select the *request method* and enter the *URL*.
		- In *Authorization Tab*, select *Basic Auth* and enter the Username and Password.
		- The Password is *Base64 encoded*.
		- Hit the API!
	+ Some useful links
		- [Baeldung - Basic Authentication](https://www.baeldung.com/spring-security-basic-authentication)
- Implemented **Ant Matchers**
	- Added *index.html* with a h1 tag in src/main/resources/static.
	- Before adding this, when we try to hit the API after giving Username and Password at 8080 instead of 8080/abc, we get White label error page as there's no endpoint at 8080. But now, the *index.html* is displayed at http://localhost:8080/.
	- ***To overcome this***, we have added `antMatchers("/", "index", "/css/*", "/js/*")` in SecurityConfig so that for these URLs the ***Basic Authentication is not required***.
	- Now, ***Username and Password is not required*** for the URLs specified in ***antMatchers***!

- Added **Application Users**
	- In the default Username and Password provided by Spring Security, the ***Username is constant***. But the ***Password is generated every time***.
	- But in ***real world***, the credentials are stored in a Database. Once the Password is set, ***it remains same*** until it is changed.
	- Things needed to access an application in a ***real world scenario*** ?
		- Username
		- Password (*Must be encoded*)
		- Role/s (*ROLE_NAME*)
		- Authorities / Permissions
		- and more...

- **Roles and Permissions**

	- For all the users of the application, we define a *Role*.
	- The Role is just a high level view.
	- *Authorities / Permissions* are given to the Roles.
	- *Multiple Roles* can be assigned to a User.
	- Defined ***Roles and Permissions*** inside Security Package.
	- Then, added these Roles to the Users.
	- This is known as ***Role Based Authentication***.

- **Disabling CSRF**

	- Created *Management API*.
	- Added a *User* with *ADMINTRAINEE* Role.
	- Now, when we hit any of the Management APIs, only *GET APIs* work.
	- *PUT, POST, DELETE and other APIs* aren't working.
	- This is because ***Spring Security by default protects*** the application.

- **Permission Based Authentication**

	- We have *Permissions* in Security Package.
	- *Permissions* are given to the *Roles*.
	- *Roles* are assigned to the *Users*.
	- Permission Based Authentication can be implemented in ***2 ways***
		- Using ***antMatchers()***
		- Using ***Annotations***

- **Using antMatchers() - By adding Authorities to Users**
	
	- Wrote a method ***getGrantedAuthorities()*** in *UserRoles*.
	- This is to specify the *Authorities* to the *Roles*.
	- In the SecurityConfig, instead of `.roles(ADMIN.name())` we can use `.authorities(ADMIN.getGrantedAuthorities())`
	- By doing this, ***along with the Roles, the Permissions are also defined*** to the User.
	- After this, the ***antMatchers()*** are added with the ***URLs and the Permissions***.
	- Now the Management APIs are accessible ***according to the Permissions***.
	- This is known as ***Permission Based Authentication***.

> ***The ORDER of antMatchers() DOES MATTER*** 

- **Using Annotations - @PreAuthorize**
	- @PreAuthorize takes a String.
		- `hasRole('ROLE_')`
		- `hasAnyRole('ROLE_')`
		- `hasAuthority('permission')`
		- `hasAnyAuthority('permission')`

- **Understanding CSRF - *Cross Site Request Forgery***
	
	> ***When to use CSRF Protection ?***
	-	It is ***recommended*** to use CSRF protection for any request that could be ***processed by a browser*** by normal users. If you are only creating a ***service*** that is used by ***non-browser clients***, you will likely want to ***disable CSRF*** protection.
	-	Hence ***CSRF is disabled*** in the code as it is a ***Service***.

- **CSRF Token**
	- To ***generate*** the CSRF Token, we comment / delete the `csrf().disable()` so that the ***CSRF is enabled*** now.
	- Run the application.
	- In ***Postman*** (From the icon next to the *Settings*), install ***Interceptor Bridge***.
	- After this, from the same page, click a link to install ***Postman Interceptor***.
	- This will redirect to the browser and prompt to install the ***Postman Interceptor Extension*** to the browser.
	- Now, back to the Interceptor Bridge in Postman, we can see ***INTERCEPTOR CONNECTED***.
	- Now the Postman Interceptor installation is ***successful***.

- **Generating CSRF Token and Hitting the APIs with CSRF Enabled**
	- Refer ***SecurityConfig.java*** for all the ***explanation!!***
	- Some useful links about ***CSRF Token***
		- [CookieCsrfTokenRepository.withHttpOnlyFalse()](https://stackoverflow.com/questions/62648098/what-does-cookie-csrftokenrepository-withhttponlyfalse-do-and-when-to-use-it)
		- [CookieCsrfTokenRepository](https://docs.spring.io/spring-security/site/docs/4.2.15.RELEASE/apidocs/org/springframework/security/web/csrf/CookieCsrfTokenRepository.html)
		- [Protection Against Exploits](https://docs.spring.io/spring-security/site/docs/5.2.x/reference/html/protection-against-exploits.html)

- **Form Based Authentication**
	- ***Username*** and ***Password***
	- ***Standard*** in most websites
	- ***Forms*** (Full Control)
	- ***Can Logout***
	- ***HTTPS*** Recommended

	+ Some useful links ***Form Based Authentication***
		- [Baeldung](https://www.baeldung.com/spring-security-login) 
		- [Javatpoint](https://www.javatpoint.com/spring-security-form-based-authentication)
		- [docs.spring.io](https://docs.spring.io/spring-security/site/docs/4.2.20.RELEASE/guides/html5/form-javaconfig.html)
		- [Howtodoinjava](https://howtodoinjava.com/spring-security/login-form-based-spring-3-security-example/)
		- [Codejava.net](https://www.codejava.net/frameworks/spring-boot/form-authentication-with-jdbc-and-mysql)
		- [Dzone.com](https://dzone.com/articles/spring-security-form-based-authentication)
	
	+ ***How it works ?***
		- ***Client*** sends ***POST*** Request with ***Username*** and ***Password*** to the ***Server***.
		- Server ***validates*** and sends ***OK***.
		- Also, the Server ***sends*** a ***Cookie SESSIONID*** to the ***Client***.
		- The ***next time***, the Client sends the ***Request along with SESSIONID*** to the ***Server***.
		- Server ***validates SESSIONID*** and sends ***Success Response***.

- **Enable Form Based Authentication**
	- Enabled by `http.formLogin()` in SecurityConfig.java
	- Now, we get the ***Login page*** which we get initially when the ***Spring Security Dependency*** was added to the application.
	- As mentioned in the above (How it works ?) section, we ***enter*** the Username and Password in the Login page.
	- The ***Spring Security validates*** the credentials and sends ***OK***.
	- Also, it ***sends a Cookie SESSIONID***.
	- To ***view*** that, on the ***Login page***, *Right Click -> Inspect -> Go to **Application** -> **Cookies** -> Select the URL which we hit -> Cookie Name - **JSESSIONID**, Session ID Value will be in the **Value***.
	- The Cookie SESSIONID is ***valid*** for ***30 Minutes***.

	+ ***Cookie SESSIONID***
		- The ***Session ID*** is stored in an ***In-Memory Database***.
		- But in ***real world***, the best practice is to store the Sessions in a ***Real Database*** such as
			- *PostgreSQL*
			- *Redis etc.*
 
	+ ***Some Useful Links***
		- [Basic Auth and Form Based Auth in same REST API](https://stackoverflow.com/questions/33739359/combining-basic-authentication-and-form-login-for-the-same-rest-api)
		- [Basic Auth and Form Based Auth with Spring Security](https://stackoverflow.com/questions/18729752/basic-and-form-based-authentication-with-spring-security-javaconfig)
		- [Form Based Authentication](https://www.javatpoint.com/spring-security-form-based-authentication)

- ***Custom Login Page***
	- A Custom Login page can be created and ***can be replaced with the existing default Login page***.
	- Refer ***SecurityConfig.java*** for the ***code***.
	- Also, I have added ***Thymeleaf Dependency*** from Spring Boot.
	- Thymeleaf is a ***Templating Engine*** which allows to do many things in regards to ***Html Files***.
	- After adding the dependency, in src/main/resources, create a folder - ***templates***.
	- Inside templates, create a file - ***login.html***
	- And added a ***Controller*** to view Custom Login Page.
	- In login.html, the ***code*** for Custom Login Page ***is taken from the Default Login Page***.
		> *In the Default Login Page -> Inspect -> Elements -> Right Click on 1st Html Tag and Copy -> Copy Element and paste it in login.html file*.
	- Now, when we hit the ***Login Page Controller***, we get the Login Page from ***login.html file***.
	
	+ ***Some useful Links for Thymeleaf***
		- [Thymeleaf](https://www.thymeleaf.org/)
		- [Baeldung](https://www.baeldung.com/spring-boot-crud-thymeleaf)
		- [TutorialsPoint](https://www.tutorialspoint.com/spring_boot/spring_boot_thymeleaf.htm)
		- [Javatpoint](https://www.javatpoint.com/spring-boot-thymeleaf-view)
		
- **Redirect After Success Login**
	- When we hit at ***8080***, it by default redirects to ***index.html*** that is in the *src/main/resources/static* folder.
	- Now, we ***change it*** to redirect to another page.
	- Refer ***SecurityConfig.java*** for the ***code***.

- **Remember Me**
	- Usually the ***Cookie SESSIONID*** expires after ***30 Minutes***.
	- Spring Security offers the ***ability to extend the expiration time*** by using the Remember Me option!
	- Refer ***SecurityConfig.java*** for the ***code***.
	- When `rememberMe()` is used, it is ***extended to 2 weeks!***
	- Added a ***Checkbox*** in login.html for Remember Me.
	- When logging in, *Inspect -> Network -> Click on Login page -> Form Data -> We can observe* `remember-me: on`
	- A ***cookie*** is sent back after logging in.
	- The ***Cookies*** are ***similar*** to the ***Cookie SessionID***.
	- In ***real world***, the Cookies are ***persisted to a real Database***.
	- But now, ***Spring Security*** uses an ***In-Memory Database*** to store the ***Cookies***.
	- We can find that in the *Login Page -> Inspect -> Network -> Click on Login page -> **Cookies***
	- The Cookie has the following:
		+ *Username*
		+ *Expiration Time*
		+ *md5 hash of the above 2 values.*
	- ***Customizing*** Cookie Expiration Time - Refer ***SecurityConfig.java*** for the ***code***.

- **Logout**
	- *Set Request Method for Logout URL* [*(Best Practice)*](https://docs.spring.io/spring-security/site/docs/4.2.20.RELEASE/apidocs/org/springframework/security/config/annotation/web/configurers/LogoutConfigurer.html#logoutUrl-java.lang.String-)
	- *Set Logout URL*
	- *Clear Authentication*
	- *Invalidate Http Session*
	- *Delete Cookies*
	- *Set the path to be redirected after Logout*

- **Logout Button**
	- In courses.html, added a Logout Button which redirects to /logout.
	- The code for Logout Button is taken from the login.html file and modified a bit.

- **Password, Username & Remember-Me Parameters**
	- Refer ***SecurityConfig.java*** for the ***code***.

- **DB Authentication**
	- Created a ***new Package*** called ***databaseAuthentication***.
	- Created a Class called *ApplicationUser* which ***implements*** *UserDetails Interface*.
	- ***Added*** unimplemented methods.
	- Then ***customized*** the class.
	- Created *ApplicationUserDAO, ApplicationUserService & FakeApplicationUserDAOService*.
	- Added `daoAuthenticationProvider()` & `configure(AuthenticationManagerBuilder auth)` in ***SecurityConfig.java***.
	- Commented the `userDetailsService()` method so that the ***Users*** are ***fetched*** from the ***Database Authentication*** implementation.

- **JSON WEB TOKEN - JWT**
	- ***Pros***
		- *Fast*
		- *Stateless*
			- It ***doesn't need to have a database!***
			- It ***doesn't need to store the session*** of the current user!
			- ***Everything is embedded*** inside the token!
		- *Used across many services*
	- ***Cons***
		- *Compromised secret key*
			- If the secret key is compromised, it leads to a trouble.
		- *No visibility to logged in users*
			- Unlike Form Based Authentication etc., we don't know when the user logs in, logs out, no history etc.
		- *Token can be stolen*
			- If the token is stolen, a hacker can pretend to be a real user in the system.
	- Some useful links
		- [*https://jwt.io/*](https://jwt.io/)
		- [*JWT Debugger Tool*](https://jwt.io/#debugger-io)
		- [*Java Jwt GitHub*](https://github.com/jwtk/jjwt)
		- [*https://flaviocopes.com/jwt/*](https://flaviocopes.com/jwt/)
		- [*https://medium.com/*](https://medium.com/@sureshdsk/how-json-web-token-jwt-authentication-works-585c4f076033)
	
	- **How it works ?**
		- ***Client*** sends ***credentials*** (Username and Password) to the ***Server***.
		- ***Server validates*** the credentials and ***Creates and Signs the Token***.
		- ***Server*** sends the ***Token*** to the ***Client***.
		- From ***next time***, the ***Client*** sends only the ***Token*** in ***each requests***.
		- ***Server validates*** the Token.

	- **What a JWT Token has ?**
		- JWT Token has ***3 parts***
			- *Header*
			- *Payload*
			- *Verify Signature*

	- **Jwt Dependencies**
		- *The dependencies are taken from* [***Java Jwt Github***](https://github.com/jwtk/jjwt)

	- **Code changes**
			- Created a package called ***jwt***.
			- Refer ***jwt*** package for the code.
			- ***Commented*** the existing configure(HttpSecurity http) method in SecurityConfig.java and ***implemented JWT Authentication in a new method*** to avoid confusion.
			- To use JWT Authentication, this method can be used.
			- To use other Spring Security Features like Basic Authentication, Form Based Authentication etc., another configure(HttpSecurity http) method can be uncommented and used.

	- ***Request Filters***
			- ***Request*** **->** *Filter1* **->** *Filter2* **->** *Filter3* **->** *FilterN* **->** ***API***
			- ***Request Filters*** are some ***classes*** that perform ***some validations*** before reaching the ***final destination (API)***.
			- In our application, ***JwtUsernameAndPasswordAuthenticationFilter.java*** is one of the filters.
			- We can have ***as many filters as we want***.
			- The ***Order*** of these Filters is ***NOT guaranteed***.
			- When the ***1st Filter is executed***, it has to pass on the ***Request and Response*** to the ***next Filter***.

	> NOTE: 
	> - Make sure the ***Expiration Time*** of the Token as not too long. Keep it like ***10 Days or 7 Days or even less***.
	>- This can ***let a User authenticate*** to your system ***as much as possible***. 
	>- A ***User*** can ***request*** for ***as many Tokens*** as he wants. Currently (With context to this application) the ***best way to fix*** this is to ***store the Tokens and User Information*** in a ***Real Database***.
	>- So when the ***User requests for another Token, we can invalidate the pre-existing ones***.
