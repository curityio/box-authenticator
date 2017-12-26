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
import io.curity.identityserver.plugin.box.descriptor.BoxAuthenticatorPluginDescriptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.curity.identityserver.sdk.Nullable;
import se.curity.identityserver.sdk.attribute.Attribute;
import se.curity.identityserver.sdk.authentication.AuthenticationResult;
import se.curity.identityserver.sdk.authentication.AuthenticatorRequestHandler;
import se.curity.identityserver.sdk.errors.ErrorCode;
import se.curity.identityserver.sdk.http.RedirectStatusCode;
import se.curity.identityserver.sdk.service.ExceptionFactory;
import se.curity.identityserver.sdk.service.authentication.AuthenticatorInformationProvider;
import se.curity.identityserver.sdk.web.Request;
import se.curity.identityserver.sdk.web.Response;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

public class BoxAuthenticatorRequestHandler implements AuthenticatorRequestHandler<Request>
{
    private static final Logger _logger = LoggerFactory.getLogger(BoxAuthenticatorRequestHandler.class);

    private final BoxAuthenticatorPluginConfig _config;
    private final AuthenticatorInformationProvider _authenticatorInformationProvider;
    private final ExceptionFactory _exceptionFactory;

    public BoxAuthenticatorRequestHandler(BoxAuthenticatorPluginConfig config,
                                          ExceptionFactory exceptionFactory,
                                          AuthenticatorInformationProvider authenticatorInformationProvider)
    {
        _config = config;
        _exceptionFactory = exceptionFactory;
        _authenticatorInformationProvider = authenticatorInformationProvider;
    }

    @Override
    public Optional<AuthenticationResult> get(Request request, Response response)
    {
        _logger.debug("GET request received for authentication authentication");

        _authenticatorInformationProvider.getFullyQualifiedAuthenticationUri();

        URI authUri = _authenticatorInformationProvider.getFullyQualifiedAuthenticationUri();
        URL redirectUri;

        try
        {
            redirectUri = new URL(authUri.toURL(), authUri.getPath() + "/" + BoxAuthenticatorPluginDescriptor.CALLBACK);
        }
        catch (MalformedURLException e)
        {
            throw _exceptionFactory.internalServerException(ErrorCode.INVALID_REDIRECT_URI,
                    "Could not create redirect URI");
        }

        _logger.debug("Redirecting to {}", redirectUri);

        String state = UUID.randomUUID().toString();
        Map<String, Collection<String>> queryStringArguments = new LinkedHashMap<>(5);
        @Nullable String scope = _config.getScope();

        _config.getSessionManager().put(Attribute.of("state", state));

        queryStringArguments.put("client_id", Collections.singleton(_config.getClientId()));
        queryStringArguments.put("redirect_uri", Collections.singleton(redirectUri.toString()));
        queryStringArguments.put("state", Collections.singleton(state));
        queryStringArguments.put("response_type", Collections.singleton("code"));

        if (scope != null)
        {
            queryStringArguments.put("scope", Collections.singleton(scope));
        }

        throw _exceptionFactory.redirectException(_config.getAuthorizationEndpoint(),
                RedirectStatusCode.MOVED_TEMPORARILY, queryStringArguments, false);
    }

    @Override
    public Optional<AuthenticationResult> post(Request request, Response response)
    {
        throw _exceptionFactory.methodNotAllowed();
    }

    @Override
    public Request preProcess(Request request, Response response)
    {
        return request;
    }
}
