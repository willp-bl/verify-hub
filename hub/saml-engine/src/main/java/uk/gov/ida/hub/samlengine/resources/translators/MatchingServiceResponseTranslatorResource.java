package uk.gov.ida.hub.samlengine.resources.translators;

import com.codahale.metrics.annotation.Timed;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.google.inject.Inject;
import uk.gov.ida.hub.samlengine.Urls;
import uk.gov.ida.hub.samlengine.contracts.InboundResponseFromMatchingServiceDto;
import uk.gov.ida.hub.samlengine.domain.SamlResponseDto;
import uk.gov.ida.hub.samlengine.services.MatchingServiceResponseTranslatorService;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

@Path(Urls.SamlEngineUrls.TRANSLATE_MATCHING_SERVICE_RESPONSE_RESOURCE)
public class MatchingServiceResponseTranslatorResource {

    private final MatchingServiceResponseTranslatorService matchingServiceResponseTranslatorService;

    @Inject
    public MatchingServiceResponseTranslatorResource(MatchingServiceResponseTranslatorService matchingServiceResponseTranslatorService) {
        this.matchingServiceResponseTranslatorService = matchingServiceResponseTranslatorService;
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Timed
    public Response translate(SamlResponseDto samlResponseDto) throws JsonProcessingException {
        InboundResponseFromMatchingServiceDto translated = matchingServiceResponseTranslatorService.translate(samlResponseDto);

        return Response.ok().entity(translated).type(MediaType.APPLICATION_JSON_TYPE).build();
    }
}
