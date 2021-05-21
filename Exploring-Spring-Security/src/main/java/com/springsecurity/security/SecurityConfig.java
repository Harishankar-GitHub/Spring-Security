package com.springsecurity.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import static com.springsecurity.security.UserRoles.*;

@Configuration
@EnableWebSecurity
// The @EnableWebSecurity is a marker annotation.
// It allows Spring to find and automatically apply the class to the global WebSecurity.
@EnableGlobalMethodSecurity(prePostEnabled = true)
// prePostEnabled is false by default.
// @EnableGlobalMethodSecurity Annotation is used to tell the Configuration that
// we want to use Annotations for Role and Permission Based Authentication.
public class SecurityConfig extends WebSecurityConfigurerAdapter
{
    private final PasswordEncoder passwordEncoder;

    @Autowired  // When we Autowire, the PasswordEncoder Bean is injected into the Constructor.
    public SecurityConfig(PasswordEncoder passwordEncoder)
    {
        this.passwordEncoder = passwordEncoder;
    }

    // After extending WebSecurityConfigurerAdapter, Right Click -> Generate -> Select Override Methods
    // to see the methods that are available to override.
    @Override
    protected void configure(HttpSecurity http) throws Exception
    {
        http
                .csrf().disable()
//                The above line can be commented so that CSRF is enabled and we can generate CSRF Token in below line.

//                .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//                .and()
//                The above line is to generate the CSRF Token.
//                Spring Security by default should generate token without the above line. But it didn't.
//                By adding the above line, the CSRF Token is generated and some configuration related to CSRF can also be done.
//                When hitting the GET API from Postman after enabling Postman Interceptor (Refer README.md),
//                we can get the CSRF Token in the Cookies section of the Response.
//                It will look like XSRF-TOKEN - Token (Cookie Name - Token)
//                Now with this Token, we can hit other APIs (POST, PUT etc.) by adding this Token in Header.
//                HeaderName - X-XSRF-TOKEN, HeaderValue - Token
//                The Token is valid for 30 Minutes.
//                Crtl+Click on CookieCsrfTokenRepository to know more.
//                Also, Find Files -> Search for CsrfFilter.class and explore.

                .authorizeRequests()
                .antMatchers("/", "index", "/css/*", "/js/*")
                    .permitAll()
                .antMatchers("/api/**").hasRole(STUDENT.name())  // "/api/**" works. "/api/*" doesn't work.
//                .antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                .antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                .antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                .antMatchers(HttpMethod.GET, "/management/api/**").hasAnyRole(ADMIN.name(), ADMINTRAINEE.name())
//                The above 4 antMatchers are Permission Based Authentication using antMatchers.
//                Commented the above antMatchers as we have used Permission Based Authentication
//                using @PreAuthorize Annotation in StudentManagementController.

                .anyRequest()
                .authenticated()
                .and()

//                .httpBasic();   // Commented this to enable Form Based Authentication in below line.

                .formLogin()                // Enabled Form Based Authentication.
                    .loginPage("/login")    // Custom Login Page.
                        .permitAll()            // Permitting the Custom Login Page.
                    .defaultSuccessUrl("/courses", true) // Default page to be redirected (Instead of index.html) after login.
                    .usernameParameter("username")  // The Parameter name here and in login.html must be same.
                    .passwordParameter("password")  // The Parameter name here and in login.html must be same.
                .and()
                .rememberMe()  // To extend the expiration time of the Cookie SESSIONID.
                                // Default expiration time is 30 Minutes.
                                // When rememberMe() is used, it is extended to 2 weeks!
                    .tokenValiditySeconds(10)   // For longer time, we can use (int) TimeUnit.DAYS.toSeconds(21) for 21 Days.
//                The above line is used to modify the expiration time of Cookies.
                    .key("SomeKey")     // This key is used to hash the details (Username, Expiration Time) from the cookies
                                    // and create md5 hash value.
                    .rememberMeParameter("remember-me") // The Parameter name here and in login.html must be same.
                .and()
                .logout()
                    .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
                    // When CSRF is enabled, Logout Request Method must be a POST.
                    // When CSRF is disabled, Logout any Request Method can be used. But the best practice is to use GET.
                    .logoutUrl("/logout")           // Setting the Path for Logout Page. If not set, default is /logout from Spring Security.
                    .clearAuthentication(true)      // Clearing Authentication.
                    .invalidateHttpSession(true)    // Invalidating Http Session.
                    .deleteCookies("JSESSIONID", "remember-me")     // Deleting cookies.
                    .logoutSuccessUrl("/login");                    // Setting the path to be redirected after logout. If not set, default is /login from Spring Security.



        // By default, Spring Security protects the application. Only GET APIs are accessible.
        // To access POST, PUT, DELETE etc, we disable CSRF.

        // We are saying, we want to authorize requests,
        // any request,
        // must be authenticated (i.e., the client must specify the username and password)
        // and
        // the mechanism that we want to enforce the authenticity of the client is by using Http Basic Authentication.

        // Permit all the requests from the URLs that are specified in antMatchers.
        // i.e., Basic Authentication is not required.

        // Permit URLs with /api/** only for the users which has STUDENT Role.

        // Permit URLs with management/api/** and methods (DELETE, POST, PUT)
        // only for users with permissions COURSE_WRITE.

        // Permit URLs with management/api/** and methods (GET)
        // only for users with role ADMIN and ADMINTRAINEE.
    }

    @Override
    @Bean
    protected UserDetailsService userDetailsService()
    {
        UserDetails jack = User.builder()
                .username("Jack")
                .password(passwordEncoder.encode("password"))
//                .roles(STUDENT.name())   // This internally will be ROLE_STUDENT
                // Commented the above line to specify the Roles along with the Authorities to the Users like below.
                .authorities(STUDENT.getGrantedAuthorities())
                .build();

        // Defining Admin User
        UserDetails jill = User.builder()
                .username("Jill")
                .password(passwordEncoder.encode("password"))
//                .roles(ADMIN.name())   // This internally will be ROLE_ADMIN
                // Commented the above line to specify the Roles along with the Authorities to the Users like below.
                .authorities(ADMIN.getGrantedAuthorities())
                .build();

        UserDetails tom = User.builder()
                .username("Tom")
                .password(passwordEncoder.encode("password"))
//                .roles(ADMINTRAINEE.name())   // This internally will be ROLE_ADMINTRAINEE
                // Commented the above line to specify the Roles along with the Authorities to the Users like below.
                .authorities(ADMINTRAINEE.getGrantedAuthorities())
                .build();

        // This method is used to retrieve User Details from a Database.
        // For now, I have configured Users here.

        // Do a Ctrl+Click on UserDetailsService and inside that check which classes
        // implements this Interface. There are around 5-6 options such as InMemoryUserDetailsManager etc.
        // I have used InMemoryUserDetailsManager.
        return new InMemoryUserDetailsManager(jack, jill, tom);
    }
}
