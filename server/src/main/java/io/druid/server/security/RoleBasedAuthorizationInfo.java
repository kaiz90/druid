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
import io.druid.java.util.common.logger.Logger;
import io.druid.server.security.db.SecurityStorageConnector;

import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RoleBasedAuthorizationInfo implements AuthorizationInfo
{
  private static final Logger log = new Logger(RoleBasedAuthorizationInfo.class);

  private final SecurityStorageConnector dbConnector;
  private final ObjectMapper mapper;
  private final String authenticationName;
  private final AuthConfig authConfig;

  private String authorizationName;
  private List<Map<String, Object>> permissions;


  public RoleBasedAuthorizationInfo(
      String authenticationName,
      SecurityStorageConnector dbConnector,
      ObjectMapper mapper,
      AuthConfig authConfig
  )
  {
    this.authenticationName = authenticationName;
    this.dbConnector = dbConnector;
    this.mapper = mapper;
    this.authConfig = authConfig;
  }

  @Override
  public Access isAuthorized(Resource resource, Action action)
  {
    if (authenticationName == null) {
      return new Access(false);
    }

    if (authorizationName == null) {
      if (authConfig.isRemapAuthNames()) {
        authorizationName = dbConnector.getAuthorizationNameFromAuthenticationName(authenticationName);
        if (authorizationName == null) {
          return new Access(false);
        }
      } else {
        authorizationName = authenticationName;
      }
      permissions = dbConnector.getPermissionsForUser(authorizationName);
    }

    // maybe optimize this later
    for (Map<String, Object> permission : permissions) {
      if (permissionCheck(resource, action, permission)) {
        return new Access(true);
      }
    }

    return new Access(false);
  }

  private boolean permissionCheck(Resource resource, Action action, Map<String, Object> permission)
  {
    ResourceAction permissionResourceAction = (ResourceAction) permission.get("resourceAction");
    if (action != permissionResourceAction.getAction()) {
      return false;
    }

    Resource permissionResource = permissionResourceAction.getResource();
    if (permissionResource.getType() != permissionResource.getType()) {
      return false;
    }

    String permissionResourceName = permissionResource.getName();
    Pattern resourceNamePattern = Pattern.compile(permissionResourceName);
    Matcher resourceNameMatcher = resourceNamePattern.matcher(resource.getName());
    return resourceNameMatcher.matches();
  }
}
