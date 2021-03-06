package uk.gov.ida.hub.policy.domain;

import com.google.common.base.Optional;
import uk.gov.ida.common.shared.security.IdGenerator;

import javax.inject.Inject;
import java.net.URI;

import static com.google.common.base.Optional.fromNullable;

public class ResponseFromHubFactory {

    private final IdGenerator idGenerator;

    @Inject
    public ResponseFromHubFactory(IdGenerator idGenerator) {
        this.idGenerator = idGenerator;
    }

    public ResponseFromHub createSuccessResponseFromHub(
            String inResponseTo,
            String matchingServiceAssertion,
            Optional<String> relayState,
            String authnRequestIssuerEntityId,
            URI assertionConsumerServiceUri) {

        return new ResponseFromHub(
                idGenerator.getId(),
                inResponseTo,
                authnRequestIssuerEntityId,
                fromNullable(matchingServiceAssertion),
                relayState,
                assertionConsumerServiceUri,
                TransactionIdaStatus.Success
        );
    }

    public ResponseFromHub createNoAuthnContextResponseFromHub(
            String inResponseTo,
            Optional<String> relayState,
            String authnRequestIssuerEntityId,
            URI assertionConsumerServiceUri) {

        return new ResponseFromHub(
                idGenerator.getId(),
                inResponseTo,
                authnRequestIssuerEntityId,
                Optional.<String>absent(),
                relayState,
                assertionConsumerServiceUri,
                TransactionIdaStatus.NoAuthenticationContext
        );
    }

    public ResponseFromHub createNoMatchResponseFromHub(
            String inResponseTo,
            Optional<String> relayState,
            String authnRequestIssuerEntityId,
            URI assertionConsumerServiceUri) {

        return new ResponseFromHub(
                idGenerator.getId(),
                inResponseTo,
                authnRequestIssuerEntityId,
                Optional.<String>absent(),
                relayState,
                assertionConsumerServiceUri,
                TransactionIdaStatus.NoMatchingServiceMatchFromHub
        );
    }

    public ResponseFromHub createAuthnFailedResponseFromHub(
            String inResponseTo,
            Optional<String> relayState,
            String authnRequestIssuerEntityId,
            URI assertionConsumerServiceUri) {

        return new ResponseFromHub(
                idGenerator.getId(),
                inResponseTo,
                authnRequestIssuerEntityId,
                Optional.<String>absent(),
                relayState,
                assertionConsumerServiceUri,
                TransactionIdaStatus.AuthenticationFailed
        );
    }

    public ResponseFromHub createRequesterErrorResponseFromHub(
            String requestId,
            Optional<String> relayState,
            String requestIssuerId,
            URI assertionConsumerServiceUri) {

        return new ResponseFromHub(
            idGenerator.getId(),
            requestId,
            requestIssuerId,
            Optional.<String>absent(),
            relayState,
            assertionConsumerServiceUri,
            TransactionIdaStatus.RequesterError
        );
    }
}