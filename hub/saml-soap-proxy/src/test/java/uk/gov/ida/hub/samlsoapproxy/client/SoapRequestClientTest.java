package uk.gov.ida.hub.samlsoapproxy.client;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Matchers;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;
import uk.gov.ida.hub.samlsoapproxy.soap.SoapMessageManager;
import uk.gov.ida.shared.utils.xml.XmlUtils;

import javax.ws.rs.BadRequestException;
import javax.ws.rs.ProcessingException;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.Invocation;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.Response;
import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class SoapRequestClientTest {

    @Mock
    private SoapMessageManager soapMessageManager;
    @Mock
    private Client client;
    @Mock
    private WebTarget webResource;
    @Mock
    private Invocation.Builder webResourceBuilder;
    @Mock
    private Document document;
    @Mock
    private Response response;

    private SoapRequestClient soapRequestClient;

    private Element soapElement;

    public SoapRequestClientTest() throws IOException, SAXException, ParserConfigurationException {
        soapElement = XmlUtils.convertToElement("<someElement/>");
    }

    @Before
    public void setUp(){
        when(soapMessageManager.wrapWithSoapEnvelope(any(Element.class))).thenReturn(document);
        when(soapMessageManager.unwrapSoapMessage(Matchers.<Document>any())).thenReturn(soapElement);
        when(client.target(any(URI.class))).thenReturn(webResource);
        when(webResource.request()).thenReturn(webResourceBuilder);
        soapRequestClient = new SoapRequestClient(soapMessageManager, client);
    }

    @Test
    public void makePost_shouldEnsureResponseInputStreamIsClosedWhenResponseCodeIsNot200(){
        when(response.getStatus()).thenReturn(502);
        when(webResourceBuilder.post(any(Entity.class))).thenReturn(response);

        try {
            soapRequestClient.makeSoapRequest(null, null);
            fail("Exception should have been thrown");
        }
        catch(SOAPRequestError e) {
            verify(response).close();
        }
    }

    @Test
    public void makePost_checkUniformInterfaceExceptionIsThrownOnNon200StatusCode() throws IOException, SAXException, ParserConfigurationException, URISyntaxException {
        when(response.getStatus()).thenReturn(303);
        when(webResourceBuilder.post(any(Entity.class))).thenReturn(response);
        Element matchingServiceRequest = XmlUtils.convertToElement("<someElement/>");
        URI matchingServiceUri = new URI("http://heyyeyaaeyaaaeyaeyaa.com/abc1");

        try {
            soapRequestClient.makeSoapRequest(matchingServiceRequest, matchingServiceUri);
            fail("Exception should have been thrown");
        }
        catch(SOAPRequestError e) { }
    }

    @Test
    public void makePost_checkProcessingExceptionIsThrown() throws IOException, SAXException,
            ParserConfigurationException, URISyntaxException, SOAPRequestError {
        ProcessingException exception = mock(ProcessingException.class);
        when(webResourceBuilder.post(any(Entity.class))).thenThrow(exception);
        Element matchingServiceRequest = XmlUtils.convertToElement("<someElement/>");
        URI matchingServiceUri = new URI("http://heyyeyaaeyaaaeyaeyaa.com/abc1");

        try {
            soapRequestClient.makeSoapRequest(matchingServiceRequest, matchingServiceUri);
            fail("Exception should have been thrown");
        }
        catch(ProcessingException e) {
            assertThat(e).isEqualTo(exception);
        }
    }

    @Test
    public void makePost_checkSOAPRequestErrorIsThrownWhenNotValidXML() throws Exception {
        when(webResourceBuilder.post(any(Entity.class))).thenReturn(response);
        when(response.readEntity(Document.class)).thenThrow(new BadRequestException());
        when(response.getStatus()).thenReturn(200);
        Element matchingServiceRequest = XmlUtils.convertToElement("<someElement/>");
        URI matchingServiceUri = new URI("http://heyyeyaaeyaaaeyaeyaa.com/abc1");

        try {
            soapRequestClient.makeSoapRequest(matchingServiceRequest, matchingServiceUri);
            fail("Exception should have been thrown");
        }
        catch(SOAPRequestError e) {
        }
        finally {
            verify(response).readEntity(Document.class);
        }
    }



    @Test
    public void makePost_aSuccessfulRequest() throws IOException, SAXException, ParserConfigurationException, URISyntaxException, SOAPRequestError {
        when(response.getStatus()).thenReturn(200);
        when(webResourceBuilder.post(any(Entity.class))).thenReturn(response);
        Element matchingServiceRequest = XmlUtils.convertToElement("<someElement/>");
        URI matchingServiceUri = new URI("http://heyyeyaaeyaaaeyaeyaa.com/abc1");

        final Element element = soapRequestClient.makeSoapRequest(matchingServiceRequest, matchingServiceUri);

        assertThat(element).isEqualTo(soapElement);
    }

}