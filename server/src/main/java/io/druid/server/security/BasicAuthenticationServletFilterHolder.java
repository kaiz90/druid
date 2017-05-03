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

package io.druid.server.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.inject.Inject;
import com.google.inject.Injector;
import io.druid.server.initialization.jetty.ServletFilterHolder;
import io.druid.server.security.db.SecurityStorageConnector;

import javax.servlet.DispatcherType;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.EnumSet;
import java.util.Map;

public class BasicAuthenticationServletFilterHolder implements ServletFilterHolder
{
  private final SecurityStorageConnector dbConnector;

  @Inject
  public BasicAuthenticationServletFilterHolder(
      SecurityStorageConnector dbConnector
  )
  {
    this.dbConnector = dbConnector;
  }

  @Override
  public Filter getFilter()
  {
    return new BasicAuthenticationFilter(null);
  }

  @Override
  public Class<? extends Filter> getFilterClass()
  {
    return BasicAuthenticationFilter.class;
  }

  @Override
  public Map<String, String> getInitParameters()
  {
    return null;
  }

  @Override
  public String getPath()
  {
    return "/*";
  }

  @Override
  public EnumSet<DispatcherType> getDispatcherType()
  {
    return null;
  }

  public static class BasicAuthenticationFilter implements Filter
  {
    private SecurityStorageConnector dbConnector;
    private final Injector injector;
    private final AuthConfig authConfig;

    public BasicAuthenticationFilter(Injector injector)
    {
      this.injector = injector;
      this.dbConnector = injector.getInstance(SecurityStorageConnector.class);
      this.authConfig = injector.getInstance(AuthConfig.class);
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException
    {

    }

    @Override
    public void doFilter(
        ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain
    ) throws IOException, ServletException
    {
      if (!authConfig.isEnabled()) {
        filterChain.doFilter(servletRequest, servletResponse);
        return;
      }

      HttpServletResponse httpResp = (HttpServletResponse) servletResponse;

      // This is the first filter in the chain, should not see an auth info token at this point
      if (servletRequest.getAttribute(AuthConfig.DRUID_AUTH_TOKEN) != null) {
        httpResp.sendError(HttpServletResponse.SC_UNAUTHORIZED);
        return;
      }

      /*
       * Move on to the next authentication filter, if any.
       * We'll send a WWW-Authenticate: Basic header in the response at the end of the chain if no other filter
       * either authenticates the request or sends its own WWW-Authenticate response.
       * (e.g. Kerberos extension would send a WWW-Authenticate: Negotiate header instead)
       */
      if (!authConfig.isEnableBasicAuthentication()) {
        filterChain.doFilter(servletRequest, servletResponse);
        return;
      }

      String userSecret = AuthenticationUtils.getBasicUserSecretFromHttpReq((HttpServletRequest) servletRequest);
      if (userSecret == null) {
        filterChain.doFilter(servletRequest, servletResponse);
        return;
      }

      String[] splits = userSecret.split(":");
      if (splits.length != 2) {
        httpResp.sendError(HttpServletResponse.SC_UNAUTHORIZED);
        return;
      }

      String user = splits[0];
      char[] password = splits[1].toCharArray();

      if (dbConnector.checkCredentials(user, password)) {
        final RoleBasedAuthorizationInfo authInfo = new RoleBasedAuthorizationInfo(
            user,
            dbConnector,
            injector.getInstance(ObjectMapper.class),
            authConfig
        );
        servletRequest.setAttribute(AuthConfig.DRUID_AUTH_TOKEN, authInfo);
        filterChain.doFilter(servletRequest, servletResponse);
      } else {
        httpResp.sendError(HttpServletResponse.SC_UNAUTHORIZED);
      }
    }

    @Override
    public void destroy()
    {

    }
  }
}
