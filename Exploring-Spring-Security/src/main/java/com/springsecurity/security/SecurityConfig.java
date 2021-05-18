package com.springsecurity.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import static com.springsecurity.security.UserPermissions.COURSE_WRITE;
import static com.springsecurity.security.UserRoles.*;

@Configuration
@EnableWebSecurity
// The @EnableWebSecurity is a marker annotation.
// It allows Spring to find and automatically apply the class to the global WebSecurity.
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
                .authorizeRequests()
                .antMatchers("/", "index", "/css/*", "/js/*")
                .permitAll()
                .antMatchers("/api/**").hasRole(STUDENT.name())  // "/api/**" works. "/api/*" doesn't work.
                .antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(COURSE_WRITE.name())
                .antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(COURSE_WRITE.name())
                .antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(COURSE_WRITE.name())
                .antMatchers(HttpMethod.GET, "/management/api/**").hasAnyRole(ADMIN.name(), ADMINTRAINEE.name())
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic();

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
                .roles(STUDENT.name())   // This internally will be ROLE_STUDENT
                .build();

        // Defining Admin User
        UserDetails jill = User.builder()
                .username("Jill")
                .password(passwordEncoder.encode("password"))
                .roles(ADMIN.name())   // This internally will be ROLE_ADMIN
                .build();

        UserDetails tom = User.builder()
                .username("Tom")
                .password(passwordEncoder.encode("password"))
                .roles(ADMINTRAINEE.name())   // This internally will be ROLE_ADMINTRAINEE
                .build();

        // This method is used to retrieve User Details from a Database.
        // For now, I have configured Users here.

        // Do a Ctrl+Click on UserDetailsService and inside that check which classes
        // implements this Interface. There are around 5-6 options such as InMemoryUserDetailsManager etc.
        // I have used InMemoryUserDetailsManager.
        return new InMemoryUserDetailsManager(jack, jill, tom);
    }
}
