/*
 *  Copyright 2017 Curity AB
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package io.curity.identityserver.plugin.box.authentication;

import io.curity.identityserver.plugin.box.config.BoxAuthenticatorPluginConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.curity.identityserver.sdk.Nullable;
import se.curity.identityserver.sdk.attribute.Attribute;
import se.curity.identityserver.sdk.attribute.Attributes;
import se.curity.identityserver.sdk.attribute.AuthenticationAttributes;
import se.curity.identityserver.sdk.attribute.ContextAttributes;
import se.curity.identityserver.sdk.attribute.SubjectAttributes;
import se.curity.identityserver.sdk.attribute.scim.v2.Address;
import se.curity.identityserver.sdk.attribute.scim.v2.Name;
import se.curity.identityserver.sdk.attribute.scim.v2.multivalued.Email;
import se.curity.identityserver.sdk.attribute.scim.v2.multivalued.PhoneNumber;
import se.curity.identityserver.sdk.attribute.scim.v2.multivalued.Photo;
import se.curity.identityserver.sdk.authentication.AuthenticationResult;
import se.curity.identityserver.sdk.authentication.AuthenticatorRequestHandler;
import se.curity.identityserver.sdk.errors.ErrorCode;
import se.curity.identityserver.sdk.http.HttpRequest;
import se.curity.identityserver.sdk.http.HttpResponse;
import se.curity.identityserver.sdk.service.ExceptionFactory;
import se.curity.identityserver.sdk.service.Json;
import se.curity.identityserver.sdk.service.authentication.AuthenticatorInformationProvider;
import se.curity.identityserver.sdk.web.Request;
import se.curity.identityserver.sdk.web.Response;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

public class CallbackRequestHandler implements AuthenticatorRequestHandler<CallbackGetRequestModel>
{
    private final static Logger _logger = LoggerFactory.getLogger(CallbackRequestHandler.class);

    private final ExceptionFactory _exceptionFactory;
    private final BoxAuthenticatorPluginConfig _config;
    private final Json _json;
    private final AuthenticatorInformationProvider _authenticatorInformationProvider;

    public CallbackRequestHandler(ExceptionFactory exceptionFactory,
                                  Json json,
                                  BoxAuthenticatorPluginConfig config,
                                  AuthenticatorInformationProvider authenticatorInformationProvider)
    {
        _exceptionFactory = exceptionFactory;
        _config = config;
        _json = json;
        _authenticatorInformationProvider = authenticatorInformationProvider;
    }

    @Override
    public CallbackGetRequestModel preProcess(Request request, Response response)
    {
        if (request.isGetRequest())
        {
            return new CallbackGetRequestModel(request);
        }
        else
        {
            throw _exceptionFactory.methodNotAllowed();
        }
    }

    @Override
    public Optional<AuthenticationResult> post(CallbackGetRequestModel requestModel, Response response)
    {
        throw _exceptionFactory.methodNotAllowed();
    }

    @Override
    public Optional<AuthenticationResult> get(CallbackGetRequestModel requestModel, Response response)
    {
        if (!Objects.isNull(requestModel.getError()))
        {

            if ("access_denied".equals(requestModel.getError()))
            {
                _logger.debug("Got an error from Box: {} - {}", requestModel.getError(), requestModel.getErrorDescription());

                throw _exceptionFactory.redirectException(
                        _authenticatorInformationProvider.getAuthenticationBaseUri().toASCIIString());
            }

            _logger.warn("Got an error from Box: {} - {}", requestModel.getError(), requestModel.getErrorDescription());

            throw _exceptionFactory.externalServiceException("Login with Box failed");
        }

        validateState(requestModel.getState());

        HttpResponse tokenResponse = _config.getTokenEndpointWebServiceClient()
                .request()
                .accept("application/json")
                .body(getFormEncodedBodyFrom(createPostData(_config.getClientId(), _config.getClientSecret(),
                        requestModel.getCode(), requestModel.getRequest().getUrl())))
                .method("POST")
                .response();

        int statusCode = tokenResponse.statusCode();

        if (statusCode != 200)
        {
            if (_logger.isDebugEnabled())
            {
                _logger.info("Got error response from token endpoint: error = {}, {}", statusCode,
                        tokenResponse.body(HttpResponse.asString()));
            }
            
            throw _exceptionFactory.internalServerException(ErrorCode.EXTERNAL_SERVICE_ERROR);
        }

        Map<String, Object> tokenResponseData = _json.fromJson(tokenResponse.body(HttpResponse.asString()));

        String accessToken = Objects.toString(tokenResponseData.get("access_token"));
        HttpResponse userInfoResponse = _config.getUserInfoEndpointWebServiceClient()
                .request()
                .accept("application/json")
                .header("Authorization", "Bearer " + accessToken)
                .method("GET")
                .response();
        statusCode = userInfoResponse.statusCode();

        if (statusCode != 200)
        {
            if (_logger.isWarnEnabled())
            {
                _logger.warn("Got an error response from the user info endpoint. Error = {}, {}", statusCode,
                        userInfoResponse.body(HttpResponse.asString()));
            }
        }

        Map<String, String> userInfoResponseData = _json.fromJson(userInfoResponse.body(HttpResponse.asString()))
                .entrySet().stream()
                .filter(e -> e.getValue() instanceof String)
                .collect(Collectors.toMap(Map.Entry::getKey, e -> (String)e.getValue()));

        List<Attribute> subjectAttributes = new LinkedList<>(), contextAttributes = new LinkedList<>();
        String login = userInfoResponseData.get("login");

        subjectAttributes.add(Attribute.of("subject",  login));
        subjectAttributes.add(Attribute.of("email", Email.of(login, true)));
        subjectAttributes.add(Attribute.of("name", Name.of(userInfoResponseData.get("name"))));
        subjectAttributes.add(Attribute.of("phone", PhoneNumber.of(userInfoResponseData.get("phone"), false)));
        subjectAttributes.add(Attribute.of("photo", Photo.of(userInfoResponseData.get("avatar_url"), false)));
        subjectAttributes.add(Attribute.of("box_id", userInfoResponseData.get("id")));
        subjectAttributes.add(Attribute.of("language", userInfoResponseData.get("language")));
        subjectAttributes.add(Attribute.of("timezone", userInfoResponseData.get("timezone")));

        @Nullable String jobTitle = userInfoResponseData.get("job_title");

        if (jobTitle != null && !jobTitle.trim().equals(""))
        {
            subjectAttributes.add(Attribute.of("job_title", jobTitle));
        }

        @Nullable String address = userInfoResponseData.get("address");

        if (address != null && !address.trim().equals(""))
        {
            subjectAttributes.add(Attribute.of("address", Address.of(address, false)));
        }

        contextAttributes.add(Attribute.of("modified_at", userInfoResponseData.get("modified_at")));
        contextAttributes.add(Attribute.of("user_type", userInfoResponseData.get("type")));
        contextAttributes.add(Attribute.of("space_amount", userInfoResponseData.get("space_amount")));
        contextAttributes.add(Attribute.of("space_used", userInfoResponseData.get("space_used")));
        contextAttributes.add(Attribute.of("max_upload_size", userInfoResponseData.get("max_upload_size")));
        contextAttributes.add(Attribute.of("status", userInfoResponseData.get("status")));
        contextAttributes.add(Attribute.of("box_access_token", accessToken));
        contextAttributes.add(Attribute.of("box_refresh_token", Objects.toString(tokenResponseData.get("refresh_token"), null)));

        AuthenticationAttributes authenticationAttributes = AuthenticationAttributes.of(
                SubjectAttributes.of(login, Attributes.of(subjectAttributes)),
                ContextAttributes.of(contextAttributes));

        return Optional.of(new AuthenticationResult(authenticationAttributes));
    }

    private static Map<String, String> createPostData(String clientId, String clientSecret, String code, String callbackUri)
    {
        Map<String, String> data = new HashMap<>(5);

        data.put("client_id", clientId);
        data.put("client_secret", clientSecret);
        data.put("code", code);
        data.put("grant_type", "authorization_code");
        data.put("redirect_uri", callbackUri);

        return data;
    }

    private static HttpRequest.BodyProcessor getFormEncodedBodyFrom(Map<String, String> data)
    {
        StringBuilder stringBuilder = new StringBuilder();

        data.entrySet().forEach(e -> appendParameter(stringBuilder, e));

        return HttpRequest.fromString(stringBuilder.toString());
    }

    private static void appendParameter(StringBuilder stringBuilder, Map.Entry<String, String> entry)
    {
        String key = entry.getKey();
        String value = entry.getValue();
        String encodedKey = urlEncodeString(key);
        stringBuilder.append(encodedKey);

        if (!Objects.isNull(value))
        {
            String encodedValue = urlEncodeString(value);
            stringBuilder.append("=").append(encodedValue);
        }

        stringBuilder.append("&");
    }

    private static String urlEncodeString(String unencodedString)
    {
        try
        {
            return URLEncoder.encode(unencodedString, StandardCharsets.UTF_8.name());
        }
        catch (UnsupportedEncodingException e)
        {
            throw new RuntimeException("This server cannot support UTF-8!", e);
        }
    }

    private void validateState(String state)
    {
        @Nullable Attribute sessionAttribute = _config.getSessionManager().get("state");

        if (sessionAttribute != null && state.equals(sessionAttribute.getValueOfType(String.class)))
        {
            _logger.debug("State matches session");
        }
        else
        {
            _logger.debug("State did not match session");

            throw _exceptionFactory.badRequestException(ErrorCode.INVALID_SERVER_STATE, "Bad state provided");
        }
    }
}