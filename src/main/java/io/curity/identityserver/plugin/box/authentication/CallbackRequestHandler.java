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
import se.curity.identityserver.sdk.authentication.AuthenticationResult;
import se.curity.identityserver.sdk.authentication.AuthenticatorRequestHandler;
import se.curity.identityserver.sdk.errors.ErrorCode;
import se.curity.identityserver.sdk.http.HttpRequest;
import se.curity.identityserver.sdk.http.HttpResponse;
import se.curity.identityserver.sdk.service.ExceptionFactory;
import se.curity.identityserver.sdk.service.Json;
import se.curity.identityserver.sdk.service.SessionManager;
import se.curity.identityserver.sdk.service.WebServiceClient;
import se.curity.identityserver.sdk.service.authentication.AuthenticatorInformationProvider;
import se.curity.identityserver.sdk.web.Request;
import se.curity.identityserver.sdk.web.Response;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

public class CallbackRequestHandler implements AuthenticatorRequestHandler<CallbackGetRequestModel>
{
    private final static Logger _logger = LoggerFactory.getLogger(CallbackRequestHandler.class);

    private final ExceptionFactory _exceptionFactory;
    private final BoxAuthenticatorPluginConfig _config;
    private final AuthenticatorInformationProvider _authenticatorInformationProvider;
    private final Json _json;

    public CallbackRequestHandler(ExceptionFactory exceptionFactory,
                                  AuthenticatorInformationProvider provider,
                                  Json json,
                                  BoxAuthenticatorPluginConfig config,
                                  AuthenticatorInformationProvider authenticatorInformationProvider)
    {
        _authenticatorInformationProvider = authenticatorInformationProvider;
        _exceptionFactory = exceptionFactory;
        _config = config;
        _json = json;
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
            _logger.info("Got an error from Box: {} - {}", requestModel.getError(), requestModel.getErrorDescription());

            throw _exceptionFactory.redirectException(
                    _authenticatorInformationProvider.getAuthenticationBaseUri().toASCIIString());
        }

        validateState(requestModel.getState());

        HttpResponse tokenResponse = _config.getWebServiceClient().withPath(_config.getTokenEndpoint().toASCIIString())
                .request()
                .accept("application/json")
                .body(getFormEncodedBodyFrom(createPostData(requestModel.getCode(), requestModel.getRequest().getUrl())))
                .method("POST")
                .response();

        if (tokenResponse.statusCode() != 200)
        {
            _logger.debug("Got error response from token endpoint: {}", response);

            throw _exceptionFactory.internalServerException(ErrorCode.EXTERNAL_SERVICE_ERROR);
        }

        Map<String, Object> tokenResponseData = _json.fromJson(tokenResponse.body(HttpResponse.asString()));

        HttpResponse userInfoResponse = _config.getWebServiceClient().withPath(_config.getUserInfoEndpoint().toASCIIString())
                .request()
                .accept("application/json")
                .header("Authorization", "Bearer " + tokenResponseData.get("access_token"))
                .method("GET")
                .response();

        Map<String, Object> userInfoResponseData = _json.fromJson(userInfoResponse.body(HttpResponse.asString()));
        AuthenticationAttributes attributes = AuthenticationAttributes.of(
                SubjectAttributes.of(userInfoResponseData.get("sub").toString(), Attributes.fromMap(userInfoResponseData)),
                ContextAttributes.of(Attributes.fromMap(tokenResponseData)));

        return Optional.of(new AuthenticationResult(attributes));
    }

    private static Map<String, String> createPostData(String code, String callbackUri)
    {
        Map<String, String> data = new HashMap<>(3);

        data.put("code", code);
        data.put("grant_type", "code");
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
