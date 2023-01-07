package demo.app;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.SecurityAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.security.kerberos.client.KerberosRestTemplate;

@SpringBootApplication
@EnableAutoConfiguration(exclude = SecurityAutoConfiguration.class)
public class Application implements CommandLineRunner {

	@Value("${app.user-principal}")
	private String userPrincipal;

	@Value("${app.keytab-location}")
	private String keytabLocation;

	@Value("${app.access-url}")
	private String accessUrl;

	@Override
	public void run(String... args) throws Exception {
		KerberosRestTemplate restTemplate =
				new KerberosRestTemplate(keytabLocation, userPrincipal);
		String response = restTemplate.getForObject(accessUrl, String.class);
		System.out.println(response);
	}

    public static void main(String[] args) throws Throwable {
    	new SpringApplicationBuilder(Application.class).web(false).run(args);
    }

}
