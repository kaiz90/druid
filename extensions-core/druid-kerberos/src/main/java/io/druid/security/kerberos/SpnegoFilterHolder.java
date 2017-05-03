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

package io.druid.security.kerberos;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Throwables;
import com.google.inject.Inject;
import io.druid.guice.annotations.Self;
import io.druid.java.util.common.logger.Logger;
import io.druid.server.DruidNode;
import io.druid.server.initialization.jetty.ServletFilterHolder;
import io.druid.server.security.AuthConfig;
import io.druid.server.security.RoleBasedAuthorizationInfo;
import io.druid.server.security.db.SecurityStorageConnector;
import org.apache.commons.codec.binary.Base64;
import org.apache.hadoop.security.SecurityUtil;
import org.apache.hadoop.security.authentication.client.KerberosAuthenticator;
import org.apache.hadoop.security.authentication.server.AuthenticationFilter;
import org.apache.hadoop.security.authentication.util.KerberosUtil;
import org.ietf.jgss.GSSManager;
import sun.security.krb5.EncryptedData;
import sun.security.krb5.EncryptionKey;
import sun.security.krb5.internal.APReq;
import sun.security.krb5.internal.EncTicketPart;
import sun.security.krb5.internal.Krb5;
import sun.security.krb5.internal.Ticket;
import sun.security.krb5.internal.crypto.KeyUsage;
import sun.security.util.DerInputStream;
import sun.security.util.DerValue;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosKey;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.kerberos.KeyTab;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.servlet.DispatcherType;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.io.File;
import java.io.IOException;
import java.security.Principal;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SpnegoFilterHolder implements ServletFilterHolder
{
  private static final Logger log = new Logger(SpnegoFilterHolder.class);
  private static final Pattern HADOOP_AUTH_COOKIE_REGEX = Pattern.compile(".*p=(\\S+)&t=.*");

  private final SpnegoFilterConfig config;
  private final AuthConfig authConfig;
  private final DruidNode node;
  private GSSManager gssManager;
  private LoginContext loginContext;
  private SecurityStorageConnector dbConnector;
  private ObjectMapper jsonMapper;


  @Inject
  public SpnegoFilterHolder(
      SpnegoFilterConfig config,
      @Self DruidNode node,
      SecurityStorageConnector dbConnector,
      ObjectMapper jsonMapper,
      AuthConfig authConfig
  )
  {
    this.config = config;
    this.node = node;
    this.dbConnector = dbConnector;
    this.jsonMapper = jsonMapper;
    this.authConfig = authConfig;
  }

  @Override
  public Filter getFilter()
  {
    return new AuthenticationFilter()
    {
      @Override
      public void init(FilterConfig filterConfig) throws ServletException
      {
        ClassLoader prevLoader = Thread.currentThread().getContextClassLoader();
        try {
          // AuthenticationHandler is created during Authenticationfilter.init using reflection with thread context class loader.
          // In case of druid since the class is actually loaded as an extension and filter init is done in main thread.
          // We need to set the classloader explicitly to extension class loader.
          Thread.currentThread().setContextClassLoader(AuthenticationFilter.class.getClassLoader());
          super.init(filterConfig);
        }
        finally {
          Thread.currentThread().setContextClassLoader(prevLoader);
        }
      }

      @Override
      public void doFilter(
        ServletRequest request, ServletResponse response, FilterChain filterChain
      ) throws IOException, ServletException
      {
        HttpServletRequest httpReq = (HttpServletRequest) request;

        // If there's already an auth token, then we have authenticated already, skip this.
        if (request.getAttribute(AuthConfig.DRUID_AUTH_TOKEN) != null) {
          filterChain.doFilter(request, response);
          return;
        }

        if (loginContext == null) {
          initializeKerberosLogin();
        }

        String path = ((HttpServletRequest) request).getRequestURI();
        if (isExcluded(path)) {
          filterChain.doFilter(request, response);
        } else {
          String clientPrincipal;
          try {
            Cookie[] cookies = httpReq.getCookies();
            if (cookies == null) {
              clientPrincipal = getPrincipalFromRequestNew((HttpServletRequest) request);
            } else {
              clientPrincipal = null;
              for (Cookie cookie : cookies) {
                if ("hadoop.auth".equals(cookie.getName())) {
                  Matcher matcher = HADOOP_AUTH_COOKIE_REGEX.matcher(cookie.getValue());
                  if (matcher.matches()) {
                    clientPrincipal = matcher.group(1);
                    break;
                  }
                }
              }
            }
          } catch (Exception ex) {
            clientPrincipal = null;
          }

          final RoleBasedAuthorizationInfo authInfo = new RoleBasedAuthorizationInfo(
              clientPrincipal,
              dbConnector,
              jsonMapper,
              authConfig
          );
          request.setAttribute(AuthConfig.DRUID_AUTH_TOKEN, authInfo);
        }
        super.doFilter(request, response, filterChain);
      }
    };
  }

  private boolean isExcluded(String path)
  {
    for (String excluded : config.getExcludedPaths()) {
      if (path.startsWith(excluded)) {
        return true;
      }
    }
    return false;
  }

  @Override
  public Class<? extends Filter> getFilterClass()
  {
    return null;
  }

  @Override
  public Map<String, String> getInitParameters()
  {
    Map<String, String> params = new HashMap<String, String>();
    try {
      params.put(
        "kerberos.principal",
        SecurityUtil.getServerPrincipal(config.getPrincipal(), node.getHost())
      );
      params.put("kerberos.keytab", config.getKeytab());
      params.put(AuthenticationFilter.AUTH_TYPE, "kerberos");
      params.put("kerberos.name.rules", config.getAuthToLocal());
      if (config.getCookieSignatureSecret() != null) {
        params.put("signature.secret", config.getCookieSignatureSecret());
      }
    }
    catch (IOException e) {
      Throwables.propagate(e);
    }
    return params;
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

  /**
   * Kerberos context configuration for the JDK GSS library.
   */
  private static class KerberosConfiguration extends Configuration
  {
    private String keytab;
    private String principal;

    public KerberosConfiguration(String keytab, String principal) {
      this.keytab = keytab;
      this.principal = principal;
    }

    @Override
    public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
      Map<String, String> options = new HashMap<String, String>();
      if (System.getProperty("java.vendor").contains("IBM")) {
        options.put("useKeytab",
                    keytab.startsWith("file://") ? keytab : "file://" + keytab);
        options.put("principal", principal);
        options.put("credsType", "acceptor");
      } else {
        options.put("keyTab", keytab);
        options.put("principal", principal);
        options.put("useKeyTab", "true");
        options.put("storeKey", "true");
        options.put("doNotPrompt", "true");
        options.put("useTicketCache", "true");
        options.put("renewTGT", "true");
        options.put("isInitiator", "false");
      }
      options.put("refreshKrb5Config", "true");
      String ticketCache = System.getenv("KRB5CCNAME");
      if (ticketCache != null) {
        if (System.getProperty("java.vendor").contains("IBM")) {
          options.put("useDefaultCcache", "true");
          // The first value searched when "useDefaultCcache" is used.
          System.setProperty("KRB5CCNAME", ticketCache);
          options.put("renewTGT", "true");
          options.put("credsType", "both");
        } else {
          options.put("ticketCache", ticketCache);
        }
      }
      if (log.isDebugEnabled()) {
        options.put("debug", "true");
      }

      return new AppConfigurationEntry[]{
          new AppConfigurationEntry(
              KerberosUtil.getKrb5LoginModuleName(),
              AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
              options),};
    }
  }

  private String getPrincipalFromRequestNew(HttpServletRequest req)
  {
    String authorization = req.getHeader(KerberosAuthenticator.AUTHORIZATION);
    if (authorization == null || !authorization.startsWith(KerberosAuthenticator.NEGOTIATE)) {
      return null;
    } else {
      authorization = authorization.substring(KerberosAuthenticator.NEGOTIATE.length()).trim();
      final Base64 base64 = new Base64(0);
      final byte[] clientToken = base64.decode(authorization);
      try {
        DerInputStream ticketStream = new DerInputStream(clientToken);
        DerValue[] values = ticketStream.getSet(clientToken.length, true);

        // see this link for AP-REQ format: https://tools.ietf.org/html/rfc1510#section-5.5.1
        for (DerValue value : values) {
          if (isValueAPReq(value)) {
            APReq apReq = new APReq(value);
            Ticket ticket = apReq.ticket;
            EncryptedData encData = ticket.encPart;
            int eType = encData.getEType();

            // find the server's key
            EncryptionKey finalKey = null;
            Subject serverSubj = loginContext.getSubject();
            Set<Object> serverCreds = serverSubj.getPrivateCredentials(Object.class);
            for (Object cred : serverCreds) {
              if (cred instanceof KeyTab) {
                KeyTab serverKeyTab = (KeyTab) cred;
                KerberosPrincipal serverPrincipal = new KerberosPrincipal(config.getPrincipal());
                KerberosKey[] serverKeys = serverKeyTab.getKeys(serverPrincipal);
                for (KerberosKey key : serverKeys) {
                  if (key.getKeyType() == eType) {
                    finalKey = new EncryptionKey(key.getKeyType(), key.getEncoded());
                    break;
                  }
                }
              }
            }

            if (finalKey == null) {
              System.out.println("Could not find matching key from server creds.");
              return null;
            }

            // decrypt the ticket with the server's key
            byte[] decryptedBytes = encData.decrypt(finalKey, KeyUsage.KU_TICKET);
            decryptedBytes = encData.reset(decryptedBytes);
            EncTicketPart decrypted = new EncTicketPart(decryptedBytes);
            String clientPrincipal = decrypted.cname.toString();
            return clientPrincipal;
          }
        }
      } catch (Exception ex) {
        System.out.println("EX MSG: " + ex.getMessage());
        return null;
      }
    }

    return null;
  }

  private boolean isValueAPReq(DerValue value) {
    return value.isConstructed((byte) Krb5.KRB_AP_REQ);
  }


  private void initializeKerberosLogin() throws ServletException
  {
    String principal;
    String keytab;

    try {
      principal = SecurityUtil.getServerPrincipal(config.getPrincipal(), node.getHost());
      if (principal == null || principal.trim().length() == 0) {
        throw new ServletException("Principal not defined in configuration");
      }
      keytab = config.getKeytab();
      if (keytab == null || keytab.trim().length() == 0) {
        throw new ServletException("Keytab not defined in configuration");
      }
      if (!new File(keytab).exists()) {
        throw new ServletException("Keytab does not exist: " + keytab);
      }

      Set<Principal> principals = new HashSet<Principal>();
      principals.add(new KerberosPrincipal(principal));
      Subject subject = new Subject(false, principals, new HashSet<Object>(), new HashSet<Object>());

      KerberosConfiguration kerberosConfiguration = new KerberosConfiguration(keytab, principal);

      log.info("Login using keytab "+keytab+", for principal "+principal);
      loginContext = new LoginContext("", subject, null, kerberosConfiguration);
      loginContext.login();

      log.info("Initialized, principal %s from keytab %s", principal, keytab);
    } catch (Exception ex) {
      throw new ServletException(ex);
    }
  }
}
