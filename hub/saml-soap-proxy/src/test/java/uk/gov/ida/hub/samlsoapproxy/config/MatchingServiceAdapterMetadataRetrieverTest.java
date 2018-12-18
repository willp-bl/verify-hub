package uk.gov.ida.hub.samlsoapproxy.config;

import certificates.values.CACertificates;
import com.google.common.collect.ImmutableList;
import keystore.CertificateEntry;
import keystore.KeyStoreResource;
import keystore.builders.KeyStoreResourceBuilder;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.RoleDescriptor;
import org.opensaml.security.credential.UsageType;
import uk.gov.ida.common.shared.security.X509CertificateFactory;
import uk.gov.ida.common.shared.security.verification.CertificateChainValidator;
import uk.gov.ida.common.shared.security.verification.exceptions.CertificateChainValidationException;
import uk.gov.ida.hub.samlsoapproxy.builders.CertificateDtoBuilder;
import uk.gov.ida.hub.samlsoapproxy.contract.MatchingServiceConfigEntityDataDto;
import uk.gov.ida.hub.samlsoapproxy.domain.CertificateDto;
import uk.gov.ida.hub.samlsoapproxy.domain.FederationEntityType;
import uk.gov.ida.hub.samlsoapproxy.exceptions.EncryptionKeyExtractionException;
import uk.gov.ida.hub.samlsoapproxy.exceptions.SigningKeyExtractionException;
import uk.gov.ida.saml.metadata.factories.DropwizardMetadataResolverFactory;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.PublicKey;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.internal.verification.VerificationModeFactory.times;
import static uk.gov.ida.saml.core.test.TestCertificateStrings.PUBLIC_SIGNING_CERTS;
import static uk.gov.ida.saml.core.test.TestCertificateStrings.TEST_RP_MS_PUBLIC_SIGNING_CERT;

@Ignore
@RunWith(MockitoJUnitRunner.class)
public class MatchingServiceAdapterMetadataRetrieverTest {

    private static final String entityId = "https://127.0.0.1/matching-service/SAML/metadata";

    @Mock
    private CertificateChainValidator certificateChainValidator;
    @Mock
    private X509CertificateFactory x509CertificateFactory;
    @Mock
    private TrustStoreForCertificateProvider trustStoreForCertificateProvider;
    @Mock
    private X509Certificate x509Certificate;
    @Mock
    private DropwizardMetadataResolverFactory dropwizardMetadataResolverFactory;
    @Mock
    private MetadataResolver metadataResolver;

    @Mock
    private EntityDescriptor msaOne;
    //    @Mock
//    private AttributeAuthorityDescriptor attributeAuthorityDescriptorOne;
    @Mock
    private EntityDescriptor msaTwo;
//    @Mock
//    private AttributeAuthorityDescriptor attributeAuthorityDescriptorTwo;

    private List<EntityDescriptor> msaEntityDescriptors = new ArrayList() {{ add(msaOne); add(msaTwo); }};

    private static KeyStoreResource msTrustStore;
    private MatchingServiceAdapterMetadataRetriever matchingServiceAdapterMetadataRetriever;

    @BeforeClass
    public static void setupResolver() {
        msTrustStore = KeyStoreResourceBuilder.aKeyStoreResource()
                .withCertificates(ImmutableList.of(new CertificateEntry("test_root_ca", CACertificates.TEST_ROOT_CA),
                        new CertificateEntry("test_rp_ca", CACertificates.TEST_RP_CA)))
                .build();
        msTrustStore.create();
    }

    @Before
    public void setup() throws CertificateException, KeyStoreException {
        when(trustStoreForCertificateProvider.getTrustStoreFor(FederationEntityType.MS)).thenReturn(msTrustStore.getKeyStore());
        when(dropwizardMetadataResolverFactory.createMetadataResolverWithClient(any(), eq(true), any())).thenReturn(metadataResolver);
        matchingServiceAdapterMetadataRetriever = new MatchingServiceAdapterMetadataRetriever(trustStoreForCertificateProvider, certificateChainValidator, dropwizardMetadataResolverFactory);

//        when(msaOne.getAttributeAuthorityDescriptor(SAMLConstants.SAML20P_NS)).thenReturn(attributeAuthorityDescriptorOne);
//        when(msaTwo.getAttributeAuthorityDescriptor(SAMLConstants.SAML20P_NS)).thenReturn(attributeAuthorityDescriptorTwo);

    }

    @Test(expected = SigningKeyExtractionException.class)
    public void getSigningKey_cannotRetreiveMetadata() throws ResolverException {
        when(metadataResolver.resolve(any())).thenThrow(mock(ResolverException.class));
        matchingServiceAdapterMetadataRetriever.getPublicSigningKeysForMSA(entityId);
    }

    @Test(expected = EncryptionKeyExtractionException.class)
    public void getEncryptionKey_cannotRetreiveMetadata() throws ResolverException {
        when(metadataResolver.resolve(any())).thenThrow(mock(ResolverException.class));
        matchingServiceAdapterMetadataRetriever.getPublicEncryptionKeyForMSA(entityId);
    }

    @Test
    public void getVerifyingKeysForEntity_shouldGetVerifyingKeysFromConfigCertificateProxy() throws Exception {
        EntityDescriptor entityDescriptor = mock(EntityDescriptor.class);
        when(metadataResolver.resolve(any())).thenReturn(ImmutableList.of(entityDescriptor));
        RoleDescriptor roleDescriptor = mock(RoleDescriptor.class);
        List<RoleDescriptor> roleDescriptors = new ArrayList<>();
        roleDescriptors.add(roleDescriptor);
        when(entityDescriptor.getRoleDescriptors()).thenReturn(roleDescriptors);
        KeyDescriptor keyDescriptor = mock(KeyDescriptor.class);
        List<KeyDescriptor> keyDescriptors = new ArrayList<>();
        keyDescriptors.add(keyDescriptor);
        when(roleDescriptor.getKeyDescriptors()).thenReturn(keyDescriptors);
        when(keyDescriptor.getUse()).thenReturn(UsageType.SIGNING);
//        when(keyDescriptor.getKeyInfo()).thenReturn(KeyInfo)

        final List<PublicKey> publicSigningKeysForMSA = matchingServiceAdapterMetadataRetriever.getPublicSigningKeysForMSA(entityId);
        assertThat(publicSigningKeysForMSA.size()).isZero();
    }

    @Test
    public void getVerifyingKeysForEntity_shouldReturnAllKeysReturnedByConfig() throws Exception {

        final CertificateDto certOneDto = getX509Certificate(TEST_RP_MS_PUBLIC_SIGNING_CERT);
//        final CertificateDto certTwoDto = getX509Certificate(SECOND_IDP_ENTITY_ID);
//        when(configProxy.getSignatureVerificationCertificates(entityId)).thenReturn(of(certOneDto, certTwoDto));
        when(x509CertificateFactory.createCertificate(certOneDto.getCertificate())).thenReturn(x509Certificate);
//        when(x509CertificateFactory.createCertificate(certTwoDto.getCertificate())).thenReturn(x509Certificate);
//        when(trustStoreForCertificateProvider.getTrustStoreFor(any(FederationEntityType.class))).thenReturn(msTrustStore);
//        when(certificateChainValidator.validate(x509Certificate, msTrustStore)).thenReturn(valid());

        matchingServiceAdapterMetadataRetriever.getPublicSigningKeysForMSA(entityId);
//        List<PublicKey> keys = configServiceKeyStore.getVerifyingKeysForEntity(entityId);

//        assertThat(keys.size()).isEqualTo(2);
    }

    @Test
    public void getVerifyingKeysForEntity_shouldValidateEachKeyReturnedByConfig() throws Exception {
//        final CertificateDto certOneDto = getX509Certificate(IDP_ENTITY_ID);
//        final CertificateDto certTwoDto = getX509Certificate(SECOND_IDP_ENTITY_ID);
//        when(configProxy.getSignatureVerificationCertificates(entityId)).thenReturn(of(certOneDto, certTwoDto));
//        when(x509CertificateFactory.createCertificate(certOneDto.getCertificate())).thenReturn(x509Certificate);
//        when(x509CertificateFactory.createCertificate(certTwoDto.getCertificate())).thenReturn(x509Certificate);
//        when(trustStoreForCertificateProvider.getTrustStoreFor(any(FederationEntityType.class))).thenReturn(msTrustStore);
//        when(certificateChainValidator.validate(x509Certificate, msTrustStore)).thenReturn(valid());

//        configServiceKeyStore.getVerifyingKeysForEntity(entityId);

//        verify(certificateChainValidator, times(2)).validate(x509Certificate, msTrustStore);
    }

    @Test
    public void getVerificationKeyForEntity_shouldThrowExceptionIfCertificateIsInvalid() throws Exception {
//        final CertificateDto certOneDto = getX509Certificate(IDP_ENTITY_ID);
//        when(configProxy.getSignatureVerificationCertificates(entityId)).thenReturn(of(certOneDto));
//        when(x509CertificateFactory.createCertificate(certOneDto.getCertificate())).thenReturn(x509Certificate);
//        when(trustStoreForCertificateProvider.getTrustStoreFor(any(FederationEntityType.class))).thenReturn(msTrustStore);
        CertPathValidatorException underlyingException = new CertPathValidatorException("Invalid Certificate");
//        when(certificateChainValidator.validate(x509Certificate, msTrustStore)).thenReturn(invalid(underlyingException));
        try {
//            configServiceKeyStore.getVerifyingKeysForEntity(entityId);
            fail(String.format("Expected [%s]", CertificateChainValidationException.class.getSimpleName()));
        } catch (CertificateChainValidationException success) {
            assertThat(success.getMessage()).isEqualTo("Certificate is not valid: Unable to get DN");
            assertThat(success.getCause()).isEqualTo(underlyingException);
        }
    }

    @Test
    public void getEncryptionKeyForEntity_shouldGetEncryptionKeysFromConfigCertificateProxy() throws Exception {

//        when(configProxy.getEncryptionCertificate(anyString())).thenReturn(aCertificateDto().build());
        when(x509CertificateFactory.createCertificate(anyString())).thenReturn(x509Certificate);
//        when(trustStoreForCertificateProvider.getTrustStoreFor(any(FederationEntityType.class))).thenReturn(msTrustStore);
//        when(certificateChainValidator.validate(x509Certificate, msTrustStore)).thenReturn(valid());

//        configServiceKeyStore.getEncryptionKeyForEntity(entityId);

//        verify(configProxy).getEncryptionCertificate(entityId);
        verify(matchingServiceAdapterMetadataRetriever, times(0)).getPublicEncryptionKeyForMSA(entityId);
    }

    @Test
    public void getEncryptionKeyForEntity_shouldValidateTheKeyReturnedByConfig() throws Exception {
//        final CertificateDto certOneDto = getX509Certificate(IDP_ENTITY_ID);
//        when(configProxy.getEncryptionCertificate(entityId)).thenReturn(certOneDto);
//        when(x509CertificateFactory.createCertificate(certOneDto.getCertificate())).thenReturn(x509Certificate);
//        when(trustStoreForCertificateProvider.getTrustStoreFor(any(FederationEntityType.class))).thenReturn(msTrustStore);
//        when(certificateChainValidator.validate(x509Certificate, msTrustStore)).thenReturn(valid());

//        configServiceKeyStore.getEncryptionKeyForEntity(entityId);

//        verify(certificateChainValidator).validate(x509Certificate, msTrustStore);
    }

    @Test
    public void getEncryptionKeyForEntity_shouldThrowExceptionIfCertificateIsInvalid() throws Exception {
//        final CertificateDto certOneDto = getX509Certificate(IDP_ENTITY_ID);
//        when(configProxy.getEncryptionCertificate(entityId)).thenReturn(certOneDto);
//        when(x509CertificateFactory.createCertificate(certOneDto.getCertificate())).thenReturn(x509Certificate);
//        when(trustStoreForCertificateProvider.getTrustStoreFor(any(FederationEntityType.class))).thenReturn(msTrustStore);
        CertPathValidatorException underlyingException = new CertPathValidatorException("Invalid Certificate");
//        when(certificateChainValidator.validate(x509Certificate, msTrustStore)).thenReturn(invalid(underlyingException));
        try {
//            configServiceKeyStore.getEncryptionKeyForEntity(entityId);
            fail(String.format("Expected [%s]", CertificateChainValidationException.class.getSimpleName()));
        } catch (CertificateChainValidationException success) {
            assertThat(success.getMessage()).isEqualTo("Certificate is not valid: Unable to get DN");
            assertThat(success.getCause()).isEqualTo(underlyingException);
        }
    }

    @Test
    public void getSigningKeyForEntity_shouldGetCertFromMetadataForMSAWhenIndicatedByConfig() throws Exception {
        MatchingServiceConfigEntityDataDto matchingServiceConfigEntityDataDto = mock(MatchingServiceConfigEntityDataDto.class);
//        when(configProxy.getMsaConfiguration(entityId)).thenReturn(Optional.ofNullable(matchingServiceConfigEntityDataDto));
        when(matchingServiceConfigEntityDataDto.getReadMetadataFromEntityId()).thenReturn(true);

//        configServiceKeyStore.getVerifyingKeysForEntity(entityId);

        verify(matchingServiceAdapterMetadataRetriever, times(1)).getPublicSigningKeysForMSA(entityId);
    }

    @Test
    public void getEncryptionKeyForEntity_shouldGetCertFromMetadataForMSAWhenIndicatedByConfig() throws Exception {
        MatchingServiceConfigEntityDataDto matchingServiceConfigEntityDataDto = mock(MatchingServiceConfigEntityDataDto.class);
//        when(configProxy.getMsaConfiguration(entityId)).thenReturn(Optional.ofNullable(matchingServiceConfigEntityDataDto));
        when(matchingServiceConfigEntityDataDto.getReadMetadataFromEntityId()).thenReturn(true);

//        configServiceKeyStore.getEncryptionKeyForEntity(entityId);

        verify(matchingServiceAdapterMetadataRetriever, times(1)).getPublicEncryptionKeyForMSA(entityId);
    }

    private static CertificateDto getX509Certificate(String entityId) throws IOException {
        return new CertificateDtoBuilder().withIssuerId(entityId).withCertificate(PUBLIC_SIGNING_CERTS.get(entityId)).build();
    }
}
