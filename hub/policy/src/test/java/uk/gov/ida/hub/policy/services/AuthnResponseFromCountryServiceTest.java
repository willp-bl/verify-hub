package uk.gov.ida.hub.policy.services;

import com.google.common.base.Optional;
import com.google.common.collect.ImmutableList;
import org.joda.time.DateTime;
import org.joda.time.DateTimeUtils;
import org.joda.time.Duration;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import uk.gov.ida.hub.policy.PolicyConfiguration;
import uk.gov.ida.hub.policy.builder.SamlAuthnResponseTranslatorDtoBuilder;
import uk.gov.ida.hub.policy.builder.domain.SessionIdBuilder;
import uk.gov.ida.hub.policy.contracts.AttributeQueryContainerDto;
import uk.gov.ida.hub.policy.contracts.EidasAttributeQueryRequestDto;
import uk.gov.ida.hub.policy.contracts.MatchingServiceConfigEntityDataDto;
import uk.gov.ida.hub.policy.contracts.SamlAuthnResponseContainerDto;
import uk.gov.ida.hub.policy.contracts.SamlAuthnResponseTranslatorDto;
import uk.gov.ida.hub.policy.domain.*;
import uk.gov.ida.hub.policy.domain.IdpIdaStatus.Status;
import uk.gov.ida.hub.policy.domain.controller.CountrySelectedStateController;
import uk.gov.ida.hub.policy.domain.exception.StateProcessingValidationException;
import uk.gov.ida.hub.policy.domain.state.CountrySelectedState;
import uk.gov.ida.hub.policy.exception.InvalidSessionStateException;
import uk.gov.ida.hub.policy.factories.SamlAuthnResponseTranslatorDtoFactory;
import uk.gov.ida.hub.policy.proxy.AttributeQueryRequest;
import uk.gov.ida.hub.policy.proxy.MatchingServiceConfigProxy;
import uk.gov.ida.hub.policy.proxy.SamlEngineProxy;
import uk.gov.ida.hub.policy.proxy.SamlSoapProxyProxy;

import java.net.URI;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Matchers.anyList;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.ida.hub.policy.builder.SamlAuthnResponseContainerDtoBuilder.aSamlAuthnResponseContainerDto;
import static uk.gov.ida.hub.policy.domain.LevelOfAssurance.LEVEL_1;
import static uk.gov.ida.hub.policy.domain.LevelOfAssurance.LEVEL_2;
import static uk.gov.ida.hub.policy.domain.ResponseAction.IdpResult.OTHER;
import static uk.gov.ida.saml.core.test.TestEntityIds.STUB_IDP_ONE;
import static uk.gov.ida.saml.core.test.TestEntityIds.TEST_RP;
import static uk.gov.ida.saml.core.test.TestEntityIds.TEST_RP_MS;

@RunWith(MockitoJUnitRunner.class)
public class AuthnResponseFromCountryServiceTest {

    private static final DateTime TIMESTAMP = DateTime.now();
    private static final URI ASSERTION_CONSUMER_SERVICE_URI = URI.create("assertion-consumer-service-uri");
    private static final SessionId SESSION_ID = SessionIdBuilder.aSessionId().build();
    private static final String REQUEST_ID = "requestId";
    private static final SamlAuthnResponseContainerDto SAML_AUTHN_RESPONSE_CONTAINER_DTO = aSamlAuthnResponseContainerDto().withSessionId(SESSION_ID).withPrincipalIPAddressAsSeenByHub("1.1.1.1").build();
    private static final SamlAuthnResponseTranslatorDto SAML_AUTHN_RESPONSE_TRANSLATOR_DTO = SamlAuthnResponseTranslatorDtoBuilder.aSamlAuthnResponseTranslatorDto().build();
    private static final String PID = "pid";
    private static final String BLOB = "blob";
    private static final String SAML_REQUEST = "SAML";
    private static final URI MSA_URI = URI.create("matching-service-uri");
    private static final boolean IS_ONBOARDING = true;
    private static final Duration MATCHING_SERVICE_RESPONSE_WAIT_PERIOD = Duration.standardMinutes(60);
    private static final Duration ASSERTION_EXPIRY = Duration.standardMinutes(60);

    private static final InboundResponseFromCountry INBOUND_RESPONSE_FROM_COUNTRY = new InboundResponseFromCountry(
        Status.Success,
        Optional.absent(),
        STUB_IDP_ONE,
        Optional.of(BLOB),
        Optional.of(PID),
        Optional.of(LEVEL_2));
    private static final EidasAttributeQueryRequestDto EIDAS_ATTRIBUTE_QUERY_REQUEST_DTO = new EidasAttributeQueryRequestDto(
        REQUEST_ID,
        TEST_RP,
        ASSERTION_CONSUMER_SERVICE_URI,
        TIMESTAMP.plus(ASSERTION_EXPIRY),
        TEST_RP_MS,
        MSA_URI,
        TIMESTAMP.plus(MATCHING_SERVICE_RESPONSE_WAIT_PERIOD),
        IS_ONBOARDING,
        LEVEL_2,
        new PersistentId(PID),
        Optional.absent(),
        Optional.absent(),
        BLOB
    );
    private static final AttributeQueryContainerDto ATTRIBUTE_QUERY_CONTAINER_DTO = new AttributeQueryContainerDto(
        SAML_REQUEST,
        MSA_URI,
        REQUEST_ID,
        TIMESTAMP,
        TEST_RP,
        IS_ONBOARDING);
    private static final AttributeQueryRequest ATTRIBUTE_QUERY_REQUEST = new AttributeQueryRequest(
        REQUEST_ID,
        TEST_RP,
        SAML_REQUEST,
        MSA_URI,
        TIMESTAMP,
        IS_ONBOARDING);

    private static final MatchingServiceConfigEntityDataDto MATCHING_SERVICE_CONFIG_ENTITY_DATA_DTO = new MatchingServiceConfigEntityDataDto(
        TEST_RP_MS,
        MSA_URI,
        TEST_RP,
        true,
        IS_ONBOARDING,
            false, URI.create("user-account-creation-uri"));

    private AuthnResponseFromCountryService service;

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Mock
    private SamlAuthnResponseTranslatorDtoFactory samlAuthnResponseTranslatorDtoFactory;

    @Mock
    private SamlEngineProxy samlEngineProxy;

    @Mock
    private SamlSoapProxyProxy samlSoapProxyProxy;

    @Mock
    private MatchingServiceConfigProxy matchingServiceConfigProxy;

    @Mock
    private PolicyConfiguration policyConfiguration;

    @Mock
    private AssertionRestrictionsFactory assertionRestrictionFactory;

    @Mock
    private CountrySelectedStateController stateController;

    @Mock
    private SessionRepository sessionRepository;

    @Mock
    private CountriesService countriesService;

    @Before
    public void setup() {
        DateTimeUtils.setCurrentMillisFixed(TIMESTAMP.getMillis());
        service = new AuthnResponseFromCountryService(
            samlEngineProxy,
            samlSoapProxyProxy,
            matchingServiceConfigProxy,
            policyConfiguration,
            sessionRepository,
            samlAuthnResponseTranslatorDtoFactory,
            countriesService,
            assertionRestrictionFactory);
        when(sessionRepository.getStateController(SESSION_ID, CountrySelectedState.class)).thenReturn(stateController);
        when(stateController.getAssertionConsumerServiceUri()).thenReturn(ASSERTION_CONSUMER_SERVICE_URI);
        when(stateController.getRequestIssuerEntityId()).thenReturn(TEST_RP);
        when(stateController.getMatchingServiceEntityId()).thenReturn(TEST_RP_MS);
        when(stateController.getRequestId()).thenReturn(REQUEST_ID);
        when(samlAuthnResponseTranslatorDtoFactory.fromSamlAuthnResponseContainerDto(SAML_AUTHN_RESPONSE_CONTAINER_DTO, TEST_RP_MS)).thenReturn(SAML_AUTHN_RESPONSE_TRANSLATOR_DTO);
        when(samlEngineProxy.translateAuthnResponseFromCountry(SAML_AUTHN_RESPONSE_TRANSLATOR_DTO)).thenReturn(INBOUND_RESPONSE_FROM_COUNTRY);
        when(samlEngineProxy.generateEidasAttributeQuery(EIDAS_ATTRIBUTE_QUERY_REQUEST_DTO)).thenReturn(ATTRIBUTE_QUERY_CONTAINER_DTO);
        when(matchingServiceConfigProxy.getMatchingService(TEST_RP_MS)).thenReturn(MATCHING_SERVICE_CONFIG_ENTITY_DATA_DTO);
        when(policyConfiguration.getMatchingServiceResponseWaitPeriod()).thenReturn(MATCHING_SERVICE_RESPONSE_WAIT_PERIOD);
        when(assertionRestrictionFactory.getAssertionExpiry()).thenReturn(TIMESTAMP.plus(ASSERTION_EXPIRY));
    }

    @After
    public void teardown() {
        DateTimeUtils.setCurrentMillisSystem();
    }

    @Test
    public void shouldCheckAnEidasResponseIsExpectedWhenSuccessfulResponseIsReceived() {
        ResponseAction responseAction = service.receiveAuthnResponseFromCountry(SESSION_ID, SAML_AUTHN_RESPONSE_CONTAINER_DTO);

        verify(sessionRepository).getStateController(SESSION_ID, CountrySelectedState.class);
        verify(samlAuthnResponseTranslatorDtoFactory).fromSamlAuthnResponseContainerDto(SAML_AUTHN_RESPONSE_CONTAINER_DTO, TEST_RP_MS);
        verify(matchingServiceConfigProxy).getMatchingService(TEST_RP_MS);
        verify(policyConfiguration).getMatchingServiceResponseWaitPeriod();
        verify(assertionRestrictionFactory).getAssertionExpiry();
        verify(samlEngineProxy).generateEidasAttributeQuery(EIDAS_ATTRIBUTE_QUERY_REQUEST_DTO);
        verify(stateController).transitionToEidasCycle0And1MatchRequestSentState(
            EIDAS_ATTRIBUTE_QUERY_REQUEST_DTO,
            SAML_AUTHN_RESPONSE_CONTAINER_DTO.getPrincipalIPAddressAsSeenByHub(),
            INBOUND_RESPONSE_FROM_COUNTRY.getIssuer());
        verify(samlSoapProxyProxy).sendHubMatchingServiceRequest(SESSION_ID, ATTRIBUTE_QUERY_REQUEST);
        ResponseAction expectedResponseAction = ResponseAction.success(SESSION_ID, false, LEVEL_2);
        assertThat(responseAction).isEqualToComparingFieldByField(expectedResponseAction);
    }

    @Test(expected = InvalidSessionStateException.class)
    public void shouldThrowAnExceptionWhenSuccessfulResponseIsReceivedAndIsInInvalidState() {
        when(sessionRepository.getStateController(SESSION_ID, CountrySelectedState.class)).thenThrow(InvalidSessionStateException.class);
        service.receiveAuthnResponseFromCountry(SESSION_ID, SAML_AUTHN_RESPONSE_CONTAINER_DTO);
    }

    @Test(expected = StateProcessingValidationException.class)
    public void shouldThrowAnExceptionWhenSuccessfulResponseIsReceivedAndCountryIsDisabled() {
        doThrow(StateProcessingValidationException.class).when(stateController).validateCountryIsIn(anyList());

        service.receiveAuthnResponseFromCountry(SESSION_ID, SAML_AUTHN_RESPONSE_CONTAINER_DTO);
    }

    @Test
    public void shouldReturnOtherResponseIfTranslationResponseFromSamlEngineNotSuccess() {
        when(samlEngineProxy.translateAuthnResponseFromCountry(SAML_AUTHN_RESPONSE_TRANSLATOR_DTO))
            .thenReturn(new InboundResponseFromCountry(Status.AuthenticationFailed, Optional.of("status"), "issuer", Optional.of("blob"), Optional.of("pid"), Optional.of(LEVEL_2)));

        ResponseAction responseAction = service.receiveAuthnResponseFromCountry(SESSION_ID, SAML_AUTHN_RESPONSE_CONTAINER_DTO);
        assertThat(responseAction.getResult()).isEqualTo(OTHER);
    }

    @Test
    public void shouldThrowIfPidNotPresentInTranslatedResponse() {
        exception.expect(StateProcessingValidationException.class);
        exception.expectMessage(String.format("Authn translation for request %s failed with missing mandatory attribute %s", REQUEST_ID, "persistentId"));
        when(samlEngineProxy.translateAuthnResponseFromCountry(SAML_AUTHN_RESPONSE_TRANSLATOR_DTO))
            .thenReturn(new InboundResponseFromCountry(Status.Success, Optional.of("status"), "issuer", Optional.of("blob"), Optional.absent(), Optional.of(LEVEL_2)));

        service.receiveAuthnResponseFromCountry(SESSION_ID, SAML_AUTHN_RESPONSE_CONTAINER_DTO);
    }

    @Test
    public void shouldThrowIfIdentityBlobNotPresentInTranslatedResponse() {
        exception.expect(StateProcessingValidationException.class);
        exception.expectMessage(String.format("Authn translation for request %s failed with missing mandatory attribute %s", REQUEST_ID, "encryptedIdentityAssertionBlob"));
        when(samlEngineProxy.translateAuthnResponseFromCountry(SAML_AUTHN_RESPONSE_TRANSLATOR_DTO))
            .thenReturn(new InboundResponseFromCountry(Status.Success, Optional.of("status"), "issuer", Optional.absent(), Optional.of("pid"), Optional.of(LEVEL_2)));

        service.receiveAuthnResponseFromCountry(SESSION_ID, SAML_AUTHN_RESPONSE_CONTAINER_DTO);
    }

    @Test
    public void shouldThrowIfLOANotPresentInTranslatedResponse() {
        exception.expect(StateProcessingValidationException.class);
        exception.expectMessage(String.format("Authn translation for request %s failed with missing mandatory attribute %s", REQUEST_ID, "levelOfAssurance"));
        when(samlEngineProxy.translateAuthnResponseFromCountry(SAML_AUTHN_RESPONSE_TRANSLATOR_DTO))
            .thenReturn(new InboundResponseFromCountry(Status.Success, Optional.of("status"), "issuer", Optional.of("blob"), Optional.of("pid"), Optional.absent()));

        service.receiveAuthnResponseFromCountry(SESSION_ID, SAML_AUTHN_RESPONSE_CONTAINER_DTO);
    }

    @Test
    public void shouldThrowIfLevelOfAssuranceNotWhatExpected() {
        exception.expect(StateProcessingValidationException.class);
        exception.expectMessage(String.format("Level of assurance in the response does not match level of assurance in the request. Was [%s] but expected [%s]", LEVEL_1, ImmutableList.of(LEVEL_2)));
        doThrow(StateProcessingValidationException.wrongLevelOfAssurance(Optional.of(LEVEL_1).transform(java.util.Optional::of).or(java.util.Optional::empty), ImmutableList.of(LEVEL_2)))
                .when(stateController).validateLevelOfAssurance(anyObject());

        service.receiveAuthnResponseFromCountry(SESSION_ID, SAML_AUTHN_RESPONSE_CONTAINER_DTO);
    }
}
