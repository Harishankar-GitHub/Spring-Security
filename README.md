# Spring Security

- Bootstrapped the application using [**start.spring.io**](https://start.spring.io/) 
- Created an **API**
- Added **Spring Security Dependency**
	- After adding the Spring Security Dependency, when the application is started and hit one of the APIs, the application redirects to the [login](http://localhost:8080/login) page.
	- The default username is ***user***
	- The default ***password*** is ***generated*** in the application console during the startup of the application.
	- [Logout](http://localhost:8080/logout) page is available as well.
	- This is known as **Form Based Authentication**.
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
