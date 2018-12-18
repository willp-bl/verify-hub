package uk.gov.ida.hub.samlengine.exceptions;

public class EncryptionKeyExtractionException extends RuntimeException {
    public EncryptionKeyExtractionException(String message, Exception causee) {
        super(message, causee);
    }
}
