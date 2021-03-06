/*
 * Licensed to Metamarkets Group Inc. (Metamarkets) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. Metamarkets licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package io.druid.cli;

import com.google.inject.Inject;
import com.google.inject.Injector;
import com.google.inject.servlet.GuiceFilter;
import io.druid.server.coordinator.DruidCoordinatorConfig;
import io.druid.server.http.OverlordProxyServlet;
import io.druid.server.http.RedirectFilter;
import io.druid.server.initialization.jetty.JettyServerInitUtils;
import io.druid.server.initialization.jetty.JettyServerInitializer;
import io.druid.server.security.AuthenticationUtils;
import io.druid.server.security.StaticResourceFilter;
import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.handler.HandlerList;
import org.eclipse.jetty.servlet.DefaultServlet;
import org.eclipse.jetty.servlet.FilterHolder;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.util.resource.Resource;
import org.eclipse.jetty.util.resource.ResourceCollection;

import java.util.Properties;

/**
 */
class CoordinatorJettyServerInitializer implements JettyServerInitializer
{
  private final DruidCoordinatorConfig config;
  private final boolean beOverlord;

  @Inject
  CoordinatorJettyServerInitializer(DruidCoordinatorConfig config, Properties properties)
  {
    this.config = config;
    this.beOverlord = CliCoordinator.isOverlord(properties);
  }

  @Override
  public void initialize(Server server, Injector injector)
  {
    final ServletContextHandler root = new ServletContextHandler(ServletContextHandler.SESSIONS);
    root.setInitParameter("org.eclipse.jetty.servlet.Default.dirAllowed", "false");

    ServletHolder holderPwd = new ServletHolder("default", DefaultServlet.class);

    root.addServlet(holderPwd, "/");
    if(config.getConsoleStatic() == null) {
      ResourceCollection staticResources;
      if (beOverlord) {
        staticResources = new ResourceCollection(
            Resource.newClassPathResource("io/druid/console"),
            Resource.newClassPathResource("static"),
            Resource.newClassPathResource("indexer_static")
        );
      } else {
        staticResources = new ResourceCollection(
            Resource.newClassPathResource("io/druid/console"),
            Resource.newClassPathResource("static")
        );
      }
      root.setBaseResource(staticResources);
    } else {
      // used for console development
      root.setResourceBase(config.getConsoleStatic());
    }

    // Add the authentication filter first
    AuthenticationUtils.addBasicAuthenticationFilter(root, injector);

    JettyServerInitUtils.addExtensionFilters(root, injector);

    // Check that requests were authorized before sending responses
    AuthenticationUtils.addPreResponseAuthorizationCheckFilter(root, injector);

    // /status should not redirect, so add first
    root.addFilter(GuiceFilter.class, "/status/*", null);

    // perform no-op authorization for these static resources
    root.addFilter(new FilterHolder(new StaticResourceFilter(injector)), "/", null);
    root.addFilter(new FilterHolder(new StaticResourceFilter(injector)), "/favicon.ico", null);
    root.addFilter(new FilterHolder(new StaticResourceFilter(injector)), "/css/*", null);
    root.addFilter(new FilterHolder(new StaticResourceFilter(injector)), "/druid.js", null);
    root.addFilter(new FilterHolder(new StaticResourceFilter(injector)), "/druid.css", null);
    root.addFilter(new FilterHolder(new StaticResourceFilter(injector)), "/pages/*", null);
    root.addFilter(new FilterHolder(new StaticResourceFilter(injector)), "/druid/*", null);
    root.addFilter(new FilterHolder(new StaticResourceFilter(injector)), "/fonts/*", null);
    root.addFilter(new FilterHolder(new StaticResourceFilter(injector)), "/old-console/*", null);
    root.addFilter(new FilterHolder(new StaticResourceFilter(injector)), "/coordinator/*", null);
    root.addFilter(new FilterHolder(new StaticResourceFilter(injector)), "/overlord/*", null);


    // redirect anything other than status to the current lead
    root.addFilter(new FilterHolder(injector.getInstance(RedirectFilter.class)), "/*", null);

    // The coordinator really needs a standarized api path
    // Can't use '/*' here because of Guice and Jetty static content conflicts
    root.addFilter(GuiceFilter.class, "/info/*", null);
    root.addFilter(GuiceFilter.class, "/druid/coordinator/*", null);
    if (beOverlord) {
      root.addFilter(GuiceFilter.class, "/druid/indexer/*", null);
    }
    // this will be removed in the next major release
    root.addFilter(GuiceFilter.class, "/coordinator/*", null);

    if (!beOverlord) {
      root.addServlet(new ServletHolder(injector.getInstance(OverlordProxyServlet.class)), "/druid/indexer/*");
    }

    HandlerList handlerList = new HandlerList();
    handlerList.setHandlers(
        new Handler[]{
            JettyServerInitUtils.getJettyRequestLogHandler(),
            JettyServerInitUtils.wrapWithDefaultGzipHandler(root)
        }
    );

    server.setHandler(handlerList);
  }
}
