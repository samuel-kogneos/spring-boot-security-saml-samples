package com.ulisesbocchio.security.saml.config;

import com.google.common.collect.ImmutableMap;
import com.ulisesbocchio.security.saml.certificate.KeystoreFactory;
import com.ulisesbocchio.security.saml.spring.security.SAMLUserDetailsServiceImpl;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.MultiThreadedHttpConnectionManager;
import org.apache.velocity.app.VelocityEngine;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.saml2.metadata.provider.ResourceBackedMetadataProvider;
import org.opensaml.util.resource.ResourceException;
import org.opensaml.xml.parse.StaticBasicParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.saml.SAMLAuthenticationProvider;
import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.saml.SAMLProcessingFilter;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.log.SAMLDefaultLogger;
import org.springframework.security.saml.log.SAMLEmptyLogger;
import org.springframework.security.saml.log.SAMLLogger;
import org.springframework.security.saml.metadata.*;
import org.springframework.security.saml.processor.*;
import org.springframework.security.saml.trust.httpclient.TLSProtocolConfigurer;
import org.springframework.security.saml.util.VelocityFactory;
import org.springframework.security.saml.websso.ArtifactResolutionProfileImpl;
import org.springframework.security.saml.websso.WebSSOProfileOptions;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;

import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Timer;

/**
 * @author Ulises Bocchio
 */
@AutoConfigureBefore(WebSecurityConfig.class)
@Configuration
@Slf4j
public class SAMLConfig {


    // *************************** OpenSAML ***************************

    @Bean
    public StaticBasicParserPool parserPool() throws XMLParserException {
        StaticBasicParserPool parserPool = new StaticBasicParserPool();
        parserPool.initialize();
        return parserPool;
    }

    // *************************** Chapter 7 - Metadata Configuration ***************************

    @Bean
    public MetadataGeneratorFilter metadataGeneratorFilter(MetadataGenerator metadataGenerator) {
        return new MetadataGeneratorFilter(metadataGenerator);
    }

    @Bean
    public MetadataDisplayFilter metadataDisplayFilter() {
        MetadataDisplayFilter filter = new MetadataDisplayFilter();
        filter.setFilterProcessesUrl("/saml/metadata");
        return filter;
    }

    @Bean
    public ExtendedMetadataDelegate extendedMetadataDelegate(StaticBasicParserPool parserPool) throws MetadataProviderException, ResourceException {
        Resource idpMetadataFile = new PathMatchingResourcePatternResolver().getResource("classpath:/idp-okta.xml");

        ResourceBackedMetadataProvider metadataProvider = new ResourceBackedMetadataProvider(
                new Timer(true),
                new SpringResourceWrapper(idpMetadataFile));
        metadataProvider.setParserPool(parserPool);

        ExtendedMetadata idpMetadata = new ExtendedMetadata();
        idpMetadata.setLocal(false);
        //todo signing
        //        idpMetadata.setSigningKey(); //todo len public key(?);

        ExtendedMetadataDelegate delegate = new ExtendedMetadataDelegate(metadataProvider, idpMetadata);
        delegate.setMetadataRequireSignature(false);
        return delegate;
    }

    @Bean
    public MetadataGenerator metadataGenerator(KeyManager keyManager) {
        ExtendedMetadata spMetadata = new ExtendedMetadata();
        spMetadata.setLocal(true);
        //TODO signing
        //        spMetadata.setSignMetadata(true);
        //        spMetadata.setSigningAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
        //        spMetadata.setSigningKey();  //todo nazov RSA klucu; public aj private ma mat rovnaky nazov(?)

        MetadataGenerator generator = new MetadataGenerator();
        generator.setKeyManager(keyManager);
        generator.setExtendedMetadata(spMetadata);
        return generator;
    }

    // *************************** Chapter 8 - Security Configuration ***************************

    //todo kluce vygenerovat a tutorial do readme
    @Bean
    public KeystoreFactory keystoreFactory(ResourceLoader resourceLoader) {
        return new KeystoreFactory(resourceLoader);
    }

    @Bean
    public KeyManager keyManager(KeystoreFactory keystoreFactory) {
        KeyStore keystore = keystoreFactory.loadKeystore("classpath:/localhost.cert", "classpath:/localhost.key.der", "localhost", "");
        return new JKSKeyManager(keystore, ImmutableMap.of("localhost", ""), "localhost");
    }

    @Bean
    public TLSProtocolConfigurer tlsProtocolConfigurer(KeyManager keyManager) {
        TLSProtocolConfigurer configurer = new TLSProtocolConfigurer();
        configurer.setKeyManager(keyManager);
        return configurer;
    }

    // *************************** Chapter 9 - SSO Configuration ***************************

    @Bean
    public AuthenticationManager authenticationManager(SAMLAuthenticationProvider samlAuthenticationProvider) {
        return new ProviderManager(Collections.singletonList(samlAuthenticationProvider));
    }

    @Bean
    public SAMLAuthenticationProvider samlAuthenticationProvider(SAMLUserDetailsServiceImpl samlUserDetailsServiceImpl, SAMLLogger samlLogger) {
        SAMLAuthenticationProvider provider = new SAMLAuthenticationProvider();
        provider.setUserDetails(samlUserDetailsServiceImpl);
        provider.setSamlLogger(samlLogger);
        provider.setForcePrincipalAsString(false);
//        provider.setConsumer(); //todo
        return provider;
    }

    @Bean
    public SAMLDefaultLogger samlLogger() {
        return new SAMLDefaultLogger();
    }

    @Bean
    public SAMLEntryPoint samlEntryPoint(SAMLLogger samlLogger) {
        WebSSOProfileOptions options = new WebSSOProfileOptions();
        options.setBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");
        //todo relays state a dalsie veci

        SAMLEntryPoint entryPoint = new SAMLEntryPoint();
        entryPoint.setDefaultProfileOptions(options);
        entryPoint.setSamlLogger(samlLogger);
        entryPoint.setFilterProcessesUrl("/saml/login");
        return entryPoint;
    }

    // *************************** Additional Configuration ***************************

    @Bean
    //todo zakomentovat, lebo ten filter pod nim by ho mal setovat a nerobi to, tak ci je ho treba vobec
    public SAMLProcessorImpl processor(StaticBasicParserPool parserPool) {
        HttpClient httpClient = new HttpClient(new MultiThreadedHttpConnectionManager());
        ArtifactResolutionProfileImpl artifactResolutionProfile = new ArtifactResolutionProfileImpl(httpClient);
        HTTPSOAP11Binding soapBinding = new HTTPSOAP11Binding(parserPool);
        artifactResolutionProfile.setProcessor(new SAMLProcessorImpl(soapBinding));

        VelocityEngine velocityEngine = VelocityFactory.getEngine();
        Collection<SAMLBinding> bindings = new ArrayList<>();
        bindings.add(new HTTPRedirectDeflateBinding(parserPool));
        bindings.add(new HTTPPostBinding(parserPool, velocityEngine));
        bindings.add(new HTTPArtifactBinding(parserPool, velocityEngine, artifactResolutionProfile));
        bindings.add(new HTTPSOAP11Binding(parserPool));
        bindings.add(new HTTPPAOS11Binding(parserPool));
        return new SAMLProcessorImpl(bindings);
    }

    @Bean(name = "samlWebSSOProcessingFilter")
    public SAMLProcessingFilter samlWebSSOProcessingFilter(AuthenticationManager authenticationManager) throws Exception {
        SAMLProcessingFilter filter = new SAMLProcessingFilter();
        filter.setAuthenticationManager(authenticationManager);
        filter.setAuthenticationSuccessHandler(successRedirectHandler());
        filter.setAuthenticationFailureHandler(authenticationFailureHandler());
        filter.setFilterProcessesUrl("/saml/SSO");
        return filter;
    }

    @Bean
    public SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler() {
        SavedRequestAwareAuthenticationSuccessHandler handler = new SavedRequestAwareAuthenticationSuccessHandler();
        handler.setDefaultTargetUrl("/home");
        return handler;
    }

    @Bean
    public SimpleUrlAuthenticationFailureHandler authenticationFailureHandler() {
        return new SimpleUrlAuthenticationFailureHandler();
//        return new SimpleUrlAuthenticationFailureHandler("/error"); //todo bez toho by mal byt 401
    }

}
