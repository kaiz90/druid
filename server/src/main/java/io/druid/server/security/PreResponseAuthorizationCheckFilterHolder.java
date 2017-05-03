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

import io.druid.java.util.common.logger.Logger;
import io.druid.server.initialization.jetty.ServletFilterHolder;
import org.eclipse.jetty.server.Response;

import javax.inject.Inject;
import javax.servlet.DispatcherType;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.WriteListener;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.util.EnumSet;
import java.util.Map;

public class PreResponseAuthorizationCheckFilterHolder implements ServletFilterHolder
{
  private static final Logger log = new Logger(PreResponseAuthorizationCheckFilterHolder.class);

  private final AuthConfig authConfig;

  @Inject
  public PreResponseAuthorizationCheckFilterHolder(
      AuthConfig authConfig
  )
  {
    this.authConfig = authConfig;
  }

  @Override
  public Filter getFilter()
  {
    class PreResponseAuthorizationCheckFilter implements Filter {

      @Override
      public void init(FilterConfig filterConfig) throws ServletException
      {

      }

      @Override
      public void doFilter(
          ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain
      ) throws IOException, ServletException
      {
        if (authConfig.isEnabled()) {
          Boolean authInfoChecked = null;
          final HttpServletResponse response = (HttpServletResponse) servletResponse;

          // make sure the original request isn't trying to fake the auth token check
          authInfoChecked = (Boolean) servletRequest.getAttribute(AuthConfig.DRUID_AUTH_TOKEN_CHECKED);
          if (authInfoChecked != null) {
            response.sendError(Response.SC_FORBIDDEN, "Authorization failure.");
            return;
          }

          // Since this is the last filter in the chain, some previous authentication filter
          // should have placed an auth token in the request.
          // If not, this is an unauthenticated request and should be denied.
          if (servletRequest.getAttribute(AuthConfig.DRUID_AUTH_TOKEN) == null) {
            response.setHeader("WWW-Authenticate", "Basic");
            response.sendError(Response.SC_UNAUTHORIZED, "Unauthorized.");
            return;
          }

          // capture the response stream before its sent to client, or we don't get a chance to modify it later
          // http://www.oracle.com/technetwork/java/filters-137243.html
          OutputStream out = servletResponse.getOutputStream();
          GenericResponseWrapper wrapper = new GenericResponseWrapper((HttpServletResponse) servletResponse);
          filterChain.doFilter(servletRequest, wrapper);

          // After response has been generated, something in the request processing path must have set
          // DRUID_AUTH_TOKEN_CHECKED (i.e. performed an authorization check). If this is not set,
          // a 403 error will be returned instead of the response.
          authInfoChecked = (Boolean) servletRequest.getAttribute(AuthConfig.DRUID_AUTH_TOKEN_CHECKED);
          authInfoChecked = true;
          // disabled for now, some endpoints like overlord console.html have no auth checks currently
          if (authInfoChecked == null) {
            response.sendError(Response.SC_FORBIDDEN, "Authorization failure.");
          } else {
            out.write(wrapper.getData());
          }
          out.close();
        } else {
          filterChain.doFilter(servletRequest, servletResponse);
        }
      }

      @Override
      public void destroy()
      {

      }
    }
    return new PreResponseAuthorizationCheckFilter();
  }

  @Override
  public Class<? extends Filter> getFilterClass()
  {
    return null;
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


  // classes from "Servlet Filters and Event Listeners"
  // https://docs.oracle.com/cd/B14099_19/web.1012/b14017/filters.htm
  private class GenericResponseWrapper extends HttpServletResponseWrapper {
    private ByteArrayOutputStream output;
    private int contentLength;
    private String contentType;

    public GenericResponseWrapper(HttpServletResponse response) {
      super(response);
      output=new ByteArrayOutputStream();
    }

    public byte[] getData() {
      return output.toByteArray();
    }

    public ServletOutputStream getOutputStream() {
      return new FilterServletOutputStream(output);
    }

    public PrintWriter getWriter() {
      return new PrintWriter(getOutputStream(),true);
    }

    public void setContentLength(int length) {
      this.contentLength = length;
      super.setContentLength(length);
    }

    public int getContentLength() {
      return contentLength;
    }

    public void setContentType(String type) {
      this.contentType = type;
      super.setContentType(type);
    }

    public String getContentType() {
      return contentType;
    }
  }

  private class FilterServletOutputStream extends ServletOutputStream {

    private DataOutputStream stream;

    public FilterServletOutputStream(OutputStream output) {
      stream = new DataOutputStream(output);
    }

    public void write(int b) throws IOException  {
      stream.write(b);
    }

    public void write(byte[] b) throws IOException  {
      stream.write(b);
    }

    public void write(byte[] b, int off, int len) throws IOException  {
      stream.write(b,off,len);
    }

    @Override
    public boolean isReady()
    {
      return false;
    }

    @Override
    public void setWriteListener(WriteListener writeListener)
    {

    }
  }
}
