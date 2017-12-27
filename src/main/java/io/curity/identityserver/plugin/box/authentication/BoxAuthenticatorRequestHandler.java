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
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
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

        String state = UUID.randomUUID().toString();
        Map<String, Collection<String>> queryStringArguments = new LinkedHashMap<>(5);

        _config.getSessionManager().put(Attribute.of("state", state));

        queryStringArguments.put("client_id", Collections.singleton(_config.getClientId()));
        queryStringArguments.put("redirect_uri", Collections.singleton(redirectUri.toString()));
        queryStringArguments.put("state", Collections.singleton(state));
        queryStringArguments.put("response_type", Collections.singleton("code"));

        Set<String> scopes = new LinkedHashSet<>(7);

        if (_config.isReadWriteAllFileAccess())
        {
            scopes.add("root_readwrite");
        }

        if (_config.isManageUsers())
        {
            scopes.add("manage_managed_users");
        }

        if (_config.isManageGroups())
        {
            scopes.add("manage_groups");
        }

        if (_config.isEnterpriseProperties())
        {
            scopes.add("manage_enterprise_properties");
        }

        if (_config.isManageDataRetention())
        {
            scopes.add("manage_data_retention");
        }

        if (_config.isManageAppUsers())
        {
            scopes.add("manage_app_users");
        }

        if (_config.isManageWebhooks())
        {
            scopes.add("manage_webhook");
        }

        queryStringArguments.put("scope", Collections.singleton(String.join(" ", scopes)));

        _logger.debug("Redirecting to {} with query string arguments {}", _config.getAuthorizationEndpoint(),
                queryStringArguments);

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
