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

package io.curity.identityserver.plugin.box.config;

import se.curity.identityserver.sdk.config.Configuration;
import se.curity.identityserver.sdk.config.annotation.DefaultBoolean;
import se.curity.identityserver.sdk.config.annotation.Description;
import se.curity.identityserver.sdk.service.ExceptionFactory;
import se.curity.identityserver.sdk.service.HttpClient;
import se.curity.identityserver.sdk.service.Json;
import se.curity.identityserver.sdk.service.SessionManager;
import se.curity.identityserver.sdk.service.WebServiceClientFactory;
import se.curity.identityserver.sdk.service.authentication.AuthenticatorInformationProvider;

import java.util.Optional;

@SuppressWarnings("InterfaceNeverImplemented")
public interface BoxAuthenticatorPluginConfig extends Configuration {
    @Description("The client applications identifier")
    String getClientId();

    @Description("The secret of the client application")
    String getClientSecret();

    @Description("The HTTP client with any proxy and TLS settings that will be used to connect to api.box.com")
    Optional<HttpClient> getHttpClient();

    @DefaultBoolean(false)
    @Description("Request a scope (root_readwrite) that allows for read and write access to all files and folders")
    boolean isReadWriteAllFileAccess();

    @DefaultBoolean(false)
    @Description("Request a scope (manage_groups) that allows the app to view, create, edit, and delete groups and group memberships")
    boolean isManageGroups();

    @DefaultBoolean(false)
    @Description("Request a scope (manage_enterprise_properties) that allows the app to to view and edit enterprise attributes and reports as well as edit and delete device pinners")
    boolean isEnterpriseProperties();

    @DefaultBoolean(false)
    @Description("Request a scope (manage_data_retention) that allows the app to view and create content retention policies")
    boolean isManageDataRetention();

    @DefaultBoolean(false)
    @Description("Request a scope (manage_app_users) that allows the app to manage its own users")
    boolean isManageAppUsers();

    @DefaultBoolean(false)
    @Description("Request a scope (manage_webhook) that allows the app to programmatically manage web hooks")
    boolean isManageWebhooks();

    // Services that don't require any configuration

    SessionManager getSessionManager();

    ExceptionFactory getExceptionFactory();

    AuthenticatorInformationProvider getAuthenticatorInformationProvider();

    WebServiceClientFactory getWebServiceClientFactory();

    Json getJson();
}
