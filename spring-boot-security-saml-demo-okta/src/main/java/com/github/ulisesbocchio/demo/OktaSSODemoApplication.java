package com.github.ulisesbocchio.demo;

import com.github.ulisesbocchio.spring.boot.security.saml.annotation.EnableSAMLSSO;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderConfigurerAdapter;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderBuilder;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.saml.websso.WebSSOProfileConsumer;
import org.springframework.security.saml.websso.WebSSOProfileConsumerImpl;
import org.springframework.security.saml.websso.WebSSOProfileOptions;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

@SpringBootApplication
@EnableSAMLSSO
public class OktaSSODemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(OktaSSODemoApplication.class, args);
    }

    @Configuration
    public static class MvcConfig extends WebMvcConfigurerAdapter {

        @Override
        public void addViewControllers(ViewControllerRegistry registry) {
            registry.addViewController("/").setViewName("index");
            registry.addViewController("/protected").setViewName("protected");
            registry.addViewController("/unprotected").setViewName("help");

        }
    }

    @Configuration
    public static class MyServiceProviderConfig extends ServiceProviderConfigurerAdapter {

        @Override
        public void configure(HttpSecurity http) throws Exception {
            // @formatter:off
            http.authorizeRequests()
                    .antMatchers("/unprotected/**")
                    .permitAll()
                .and()
                    .anonymous();
            // @formatter:on
        }

        @Override
        public void configure(ServiceProviderBuilder serviceProvider) throws Exception {
            WebSSOProfileConsumerImpl consumer = new WebSSOProfileConsumerImpl(); //TODO: maybe don't create new one but try to get a created one instead.
            consumer.setMaxAuthenticationAge(2);

            // @formatter:off
            serviceProvider
                .metadataGenerator()
//                .entityId("http://www.okta.com/exkfplpbpexh7VohS0h7")
                .bindingsSSO("artifact", "post", "paos")
            .and()
                .ecpProfile()
            .and()
                .sso()
                .defaultSuccessURL("/home")
                .idpSelectionPageURL("/idpselection")
            .and()
                .metadataManager()
                .metadataLocations("classpath:/idp-okta.xml")
                .refreshCheckInterval(0)
            .and()
                .extendedMetadata()
                .ecpEnabled(true)
                .idpDiscoveryEnabled(true)//set to false for no IDP Selection page.
            .and()
                .keyManager()
                .privateKeyDERLocation("classpath:/localhost.key.der")
                .publicKeyPEMLocation("classpath:/localhost.cert")
            .and()
                .ssoProfileConsumer(consumer);
            // @formatter:on

        }
    }
}
