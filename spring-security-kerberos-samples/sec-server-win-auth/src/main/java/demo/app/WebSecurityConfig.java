package demo.app;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.FileSystemResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.servlet.configuration.EnableWebMvcSecurity;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.extensions.kerberos.KerberosServiceAuthenticationProvider;
import org.springframework.security.extensions.kerberos.SunJaasKerberosTicketValidator;
import org.springframework.security.extensions.kerberos.web.SpnegoAuthenticationProcessingFilter;
import org.springframework.security.extensions.kerberos.web.SpnegoEntryPoint;
import org.springframework.security.ldap.authentication.ad.ActiveDirectoryLdapAuthenticationProvider;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
@EnableWebMvcSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	@Value("${app.ad-domain}")
	private String adDomain;

	@Value("${app.ad-server}")
	private String adServer;

	@Value("${app.service-principal}")
	private String servicePrincipal;

	@Value("${app.keytab-location}")
	private String keytabLocation;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.exceptionHandling()
				.authenticationEntryPoint(spnegoEntryPoint())
				.and()
			.authorizeRequests()
				.antMatchers("/", "/home").permitAll()
				.anyRequest().authenticated()
				.and()
			.formLogin()
				.loginPage("/login").permitAll()
				.and()
			.logout()
				.permitAll()
				.and()
			.addFilterBefore(
					spnegoAuthenticationProcessingFilter(authenticationManagerBean()),
					BasicAuthenticationFilter.class);
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth
			.authenticationProvider(activeDirectoryLdapAuthenticationProvider())
			.authenticationProvider(kerberosServiceAuthenticationProvider());
	}

	@Bean
	public ActiveDirectoryLdapAuthenticationProvider activeDirectoryLdapAuthenticationProvider() {
		return new ActiveDirectoryLdapAuthenticationProvider(adDomain, adServer);
	}

	@Bean
	public SpnegoEntryPoint spnegoEntryPoint() {
		return new SpnegoEntryPoint("/login");
	}

	@Bean
	public SpnegoAuthenticationProcessingFilter spnegoAuthenticationProcessingFilter(
			AuthenticationManager authenticationManager) {
		SpnegoAuthenticationProcessingFilter filter = new SpnegoAuthenticationProcessingFilter();
		filter.setAuthenticationManager(authenticationManager);
		return filter;
	}

	@Bean
	public KerberosServiceAuthenticationProvider kerberosServiceAuthenticationProvider() {
		KerberosServiceAuthenticationProvider provider = new KerberosServiceAuthenticationProvider();
		provider.setTicketValidator(sunJaasKerberosTicketValidator());
		provider.setUserDetailsService(dummyUserDetailsService());
		return provider;
	}

	@Bean
	public SunJaasKerberosTicketValidator sunJaasKerberosTicketValidator() {
		SunJaasKerberosTicketValidator ticketValidator = new SunJaasKerberosTicketValidator();
		ticketValidator.setServicePrincipal(servicePrincipal);
		ticketValidator.setKeyTabLocation(new FileSystemResource(keytabLocation));
		ticketValidator.setDebug(true);
		return ticketValidator;
	}

	@Bean
	public DummyUserDetailsService dummyUserDetailsService() {
		return new DummyUserDetailsService();
	}

	static class DummyUserDetailsService implements UserDetailsService {

		public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
			return new User(username, "notUsed", true, true, true, true,
					AuthorityUtils.createAuthorityList("ROLE_USER"));
		}

	}

}
