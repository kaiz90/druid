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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class AuthConfig
{
  /**
   * Use this String as the attribute name for the request attribute to pass {@link AuthorizationInfo}
   * from the servlet filter to the jersey resource
   * */
  public static final String DRUID_AUTH_TOKEN = "Druid-Auth-Token";

  /**
   * HTTP attribute set when a static method in AuthorizationUtils performs an authorization check on the request.
   */
  public static final String DRUID_AUTH_TOKEN_CHECKED = "Druid-Auth-Token-Checked";

  public AuthConfig() {
    this(false, false, null, null, false);
  }

  @JsonCreator
  public AuthConfig(
      @JsonProperty("enabled") boolean enabled,
      @JsonProperty("enableBasicAuthentication") boolean enableBasicAuthentication,
      @JsonProperty("systemPrincipal") String systemPrincipal,
      @JsonProperty("systemPrincipalSecret") String systemPrincipalSecret,
      @JsonProperty("remapAuthNames") boolean remapAuthNames
  ){
    this.enabled = enabled;
    this.enableBasicAuthentication = enableBasicAuthentication;
    this.systemPrincipal = systemPrincipal;
    this.systemPrincipalSecret = systemPrincipalSecret;
    this.remapAuthNames = remapAuthNames;
  }

  /**
   * If druid.auth.enabled is set to true then an implementation of AuthorizationInfo
   * must be provided and it must be set as a request attribute possibly inside the servlet filter
   * injected in the filter chain using your own extension
   * */
  @JsonProperty
  private final boolean enabled;

  @JsonProperty
  private final boolean enableBasicAuthentication;

  @JsonProperty
  private final String systemPrincipal;

  @JsonProperty
  private final String systemPrincipalSecret;

  @JsonProperty
  private final boolean remapAuthNames;

  public boolean isEnabled()
  {
    return enabled;
  }

  public boolean isEnableBasicAuthentication()
  {
    return enableBasicAuthentication;
  }

  public String getSystemPrincipal()
  {
    return systemPrincipal;
  }

  public String getSystemPrincipalSecret()
  {
    return systemPrincipalSecret;
  }

  public boolean isRemapAuthNames()
  {
    return remapAuthNames;
  }

  @Override
  public boolean equals(Object o)
  {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    AuthConfig that = (AuthConfig) o;

    if (isEnabled() != that.isEnabled()) {
      return false;
    }
    return isEnableBasicAuthentication() == that.isEnableBasicAuthentication();

  }

  @Override
  public int hashCode()
  {
    int result = (isEnabled() ? 1 : 0);
    result = 31 * result + (isEnableBasicAuthentication() ? 1 : 0);
    return result;
  }

  @Override
  public String toString()
  {
    return "AuthConfig{" +
           "enabled=" + enabled + "," +
           "enableBasicAuthentication=" + enableBasicAuthentication +
           '}';
  }
}
