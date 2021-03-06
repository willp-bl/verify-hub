package uk.gov.ida.hub.config.domain;

import com.google.common.collect.ImmutableList;
import uk.gov.ida.common.shared.security.verification.CertificateChainValidator;
import uk.gov.ida.hub.config.dto.InvalidCertificateDto;
import uk.gov.ida.hub.config.truststore.TrustStoreForCertificateProvider;

import javax.inject.Inject;

import static uk.gov.ida.hub.config.exceptions.ConfigValidationException.createInvalidCertificatesException;

public class ThrowingCertificateChainConfigValidator extends CertificateChainConfigValidator {

    @Inject
    public ThrowingCertificateChainConfigValidator(final TrustStoreForCertificateProvider trustStoreForCertificateProvider, final CertificateChainValidator certificateChainValidator) {
        super(trustStoreForCertificateProvider, certificateChainValidator);
    }

    @Override
    void handleInvalidCertificates(ImmutableList<InvalidCertificateDto> invalidCertificates) {
        if (!invalidCertificates.isEmpty()) {
            throw createInvalidCertificatesException(invalidCertificates);
        }
    }
}
