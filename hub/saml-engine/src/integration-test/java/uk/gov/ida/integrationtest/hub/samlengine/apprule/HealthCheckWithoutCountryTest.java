package uk.gov.ida.integrationtest.hub.samlengine.apprule;

import helpers.JerseyClientConfigurationBuilder;
import io.dropwizard.client.JerseyClientBuilder;
import io.dropwizard.client.JerseyClientConfiguration;
import io.dropwizard.util.Duration;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import uk.gov.ida.integrationtest.hub.samlengine.apprule.support.ConfigStubRule;
import uk.gov.ida.integrationtest.hub.samlengine.apprule.support.MetadataRule;
import uk.gov.ida.integrationtest.hub.samlengine.apprule.support.SamlEngineAppRule;

import javax.ws.rs.client.Client;

import static io.dropwizard.testing.ConfigOverride.config;
import static org.assertj.core.api.Assertions.assertThat;
import static uk.gov.ida.hub.samlengine.SamlEngineModule.COUNTRY_METADATA_HEALTH_CHECK;
import static uk.gov.ida.hub.samlengine.SamlEngineModule.VERIFY_METADATA_HEALTH_CHECK;

public class HealthCheckWithoutCountryTest {

    private static Client client;

    @ClassRule
    public static ConfigStubRule configStub = new ConfigStubRule();

    @ClassRule
    public static SamlEngineAppRule samlEngineAppRule = new SamlEngineAppRule(false,
        config("configUri", configStub.baseUri().build().toASCIIString())
    );

    @BeforeClass
    public static void setupClass() throws Exception {
        JerseyClientConfiguration jerseyClientConfiguration = JerseyClientConfigurationBuilder
            .aJerseyClientConfiguration().withTimeout(Duration.seconds(10)).build();
        client = new JerseyClientBuilder(samlEngineAppRule.getEnvironment()).using(jerseyClientConfiguration)
            .build(HealthCheckWithoutCountryTest.class.getSimpleName());
    }

    @Test
    public void shouldContainBothVerifyAndCountryMetadataHealthChecks() {
        assertThat(samlEngineAppRule.getEnvironment().healthChecks().getNames().contains(VERIFY_METADATA_HEALTH_CHECK)).isTrue();
        assertThat(samlEngineAppRule.getEnvironment().healthChecks().getNames().contains(COUNTRY_METADATA_HEALTH_CHECK)).isFalse();
    }
}
