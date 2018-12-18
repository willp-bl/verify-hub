package uk.gov.ida.hub.samlsoapproxy.exceptions;

public class EncryptionKeyExtractionException extends RuntimeException {
    public EncryptionKeyExtractionException(String message, Exception causee) {
        super(message, causee);
    }
}
