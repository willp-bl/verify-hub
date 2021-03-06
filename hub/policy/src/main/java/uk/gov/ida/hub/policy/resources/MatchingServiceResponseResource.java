package uk.gov.ida.hub.policy.resources;

import com.codahale.metrics.annotation.Timed;
import uk.gov.ida.hub.policy.contracts.SamlResponseDto;
import uk.gov.ida.hub.policy.domain.SessionId;
import uk.gov.ida.hub.policy.services.MatchingServiceResponseService;

import javax.inject.Inject;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import static uk.gov.ida.hub.policy.Urls.PolicyUrls.ATTRIBUTE_QUERY_RESPONSE_RESOURCE;
import static uk.gov.ida.hub.policy.Urls.SharedUrls.SESSION_ID_PARAM;

@Path(ATTRIBUTE_QUERY_RESPONSE_RESOURCE)
@Consumes(MediaType.APPLICATION_JSON)
public class MatchingServiceResponseResource {

    private final MatchingServiceResponseService matchingServiceResponseService;

    @Inject
    public MatchingServiceResponseResource(MatchingServiceResponseService matchingServiceResponseService) {
        this.matchingServiceResponseService = matchingServiceResponseService;
    }

    @POST
    @Timed
    public Response receiveAttributeQueryResponseFromMatchingService(@PathParam(SESSION_ID_PARAM) SessionId sessionId, SamlResponseDto samlResponse) {
        matchingServiceResponseService.handleSuccessResponse(sessionId, samlResponse);
        // HubMatchingServiceResponseReceiverProxy does nothing with this response
        return Response.ok().build();
    }

}
