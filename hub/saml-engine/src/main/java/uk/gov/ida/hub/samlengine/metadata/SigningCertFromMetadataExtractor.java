package uk.gov.ida.hub.samlengine.metadata;

import com.google.common.collect.ImmutableList;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import org.apache.xml.security.exceptions.Base64DecodingException;
import org.apache.xml.security.utils.Base64;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.security.credential.UsageType;
import uk.gov.ida.hub.samlengine.exceptions.CertificateForCurrentPrivateSigningKeyNotFoundInMetadataException;
import uk.gov.ida.hub.samlengine.exceptions.UnableToResolveSigningCertsForHubException;

import javax.inject.Inject;
import javax.inject.Named;
import java.io.ByteArrayInputStream;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.google.common.base.Throwables.propagate;
import static uk.gov.ida.hub.samlengine.SamlEngineModule.VERIFY_METADATA_RESOLVER;

public class SigningCertFromMetadataExtractor {

    private final MetadataResolver metadataResolver;
    private final String hubEntityId;

    @Inject
    public SigningCertFromMetadataExtractor(@Named(VERIFY_METADATA_RESOLVER) MetadataResolver metadataResolver,
                                            @Named("HubEntityId") String hubEntityId) {
        this.metadataResolver = metadataResolver;
        this.hubEntityId = hubEntityId;
    }

    public X509Certificate getSigningCertForCurrentSigningKey(PublicKey publicSigningKey) {
        CriteriaSet criteriaSet = new CriteriaSet(new EntityIdCriterion(hubEntityId));
        try {
            for(EntityDescriptor entityDescriptor : metadataResolver.resolve(criteriaSet)) {
                final List<X509Certificate> certificates = getCertificates(entityDescriptor);
                for(X509Certificate certificate : certificates) {
                    if(publicSigningKey.equals(certificate.getPublicKey())) {
                        return certificate;
                    }
                }
            }
        } catch (ResolverException e) {
            throw new UnableToResolveSigningCertsForHubException(e);
        }
        throw new CertificateForCurrentPrivateSigningKeyNotFoundInMetadataException();
    }

    private List<X509Certificate> getCertificates(EntityDescriptor descriptor) {
        return descriptor.getSPSSODescriptor(SAMLConstants.SAML20P_NS).getKeyDescriptors().stream()
                .filter(keyDescriptor -> keyDescriptor.getUse().equals(UsageType.SIGNING))
                .flatMap(this::getCertificates)
                .collect(Collectors.collectingAndThen(Collectors.toList(), ImmutableList::copyOf));
    }

    private Stream<X509Certificate> getCertificates(KeyDescriptor keyDescriptor) {
        return keyDescriptor.getKeyInfo().getX509Datas().stream()
                .flatMap(x -> x.getX509Certificates().stream())
                .map(x -> getCertificate(x));
    }

    private X509Certificate getCertificate(org.opensaml.xmlsec.signature.X509Certificate x509Certificate) {
        try {
            byte[] derValue = Base64.decode(x509Certificate.getValue());
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate)certificateFactory.generateCertificate(new ByteArrayInputStream(derValue));
            return certificate;
        } catch (Base64DecodingException | CertificateException e) {
            throw propagate(e);
        }
    }

}
