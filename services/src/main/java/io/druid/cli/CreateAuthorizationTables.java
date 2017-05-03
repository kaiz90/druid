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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import com.google.inject.Binder;
import com.google.inject.Injector;
import com.google.inject.Key;
import com.google.inject.Module;

import io.airlift.airline.Command;
import io.airlift.airline.Option;
import io.druid.guice.JsonConfigProvider;
import io.druid.guice.annotations.Self;
import io.druid.java.util.common.logger.Logger;
import io.druid.server.DruidNode;
import io.druid.server.security.Action;
import io.druid.server.security.Resource;
import io.druid.server.security.ResourceAction;
import io.druid.server.security.ResourceType;
import io.druid.server.security.db.AuthorizationStorageConnectorConfig;
import io.druid.server.security.db.SecurityStorageConnector;

import java.util.List;

@Command(
    name = "authorization-init",
    description = "Initialize Authorization Storage"
)
public class CreateAuthorizationTables extends GuiceRunnable
{
  @Option(name = "--connectURI", description = "Database JDBC connection string", required = true)
  private String connectURI;

  @Option(name = "--user", description = "Database username", required = true)
  private String user;

  @Option(name = "--password", description = "Database password", required = true)
  private String password;

  @Option(name = "--base", description = "Base table name")
  private String base;

  private static final Logger log = new Logger(CreateAuthorizationTables.class);

  public CreateAuthorizationTables()
  {
    super(log);
  }

  @Override
  protected List<? extends Module> getModules()
  {
    return ImmutableList.<Module>of(
        new Module()
        {
          @Override
          public void configure(Binder binder)
          {
            JsonConfigProvider.bindInstance(
                binder, Key.get(AuthorizationStorageConnectorConfig.class), new AuthorizationStorageConnectorConfig()
                {
                  @Override
                  public String getConnectURI()
                  {
                    return connectURI;
                  }

                  @Override
                  public String getUser()
                  {
                    return user;
                  }

                  @Override
                  public String getPassword()
                  {
                    return password;
                  }
                }
            );
            JsonConfigProvider.bindInstance(
                binder, Key.get(DruidNode.class, Self.class), new DruidNode("tools", "localhost", -1)
            );
          }
        }
    );
  }

  @Override
  public void run()
  {
    final Injector injector = makeInjector();
    SecurityStorageConnector dbConnector = injector.getInstance(SecurityStorageConnector.class);
    ObjectMapper jsonMapper = injector.getInstance(ObjectMapper.class);

    dbConnector.createUserTable();
    dbConnector.createAuthenticationToAuthorizationNameMappingTable();
    dbConnector.createRoleTable();
    dbConnector.createPermissionTable();
    dbConnector.createUserRoleTable();
    dbConnector.createUserCredentialsTable();

    setupDefaultAdmin(dbConnector, jsonMapper);
    setupInternalDruidSystemUser(dbConnector, jsonMapper);
  }

  private static void setupInternalDruidSystemUser(SecurityStorageConnector dbConnector, ObjectMapper jsonMapper)
  {
    dbConnector.createUser("druid_system");
    dbConnector.createRole("druid_system");
    dbConnector.assignRole("druid_system", "druid_system");

    ResourceAction datasourceR = new ResourceAction(
        new Resource(".*", ResourceType.DATASOURCE),
        Action.READ
    );

    ResourceAction datasourceW = new ResourceAction(
        new Resource(".*", ResourceType.DATASOURCE),
        Action.WRITE
    );

    List<ResourceAction> resActs = Lists.newArrayList(datasourceR, datasourceW);

    for (ResourceAction resAct : resActs) {
      try {
        byte[] serializedPermission = jsonMapper.writeValueAsBytes(resAct);
        dbConnector.addPermission("druid_system", serializedPermission, null);
      } catch (JsonProcessingException jpe) {
        log.error("WTF? Couldn't serialize internal druid system permission.");
      }
    }

    dbConnector.setUserCredentials("druid_system", "druid".toCharArray());

    dbConnector.createAuthenticationToAuthorizationNameMapping("druid_system", "druid_system");
  }

  private static void setupDefaultAdmin(SecurityStorageConnector dbConnector, ObjectMapper jsonMapper)
  {
    dbConnector.createUser("admin");
    dbConnector.createRole("admin");
    dbConnector.assignRole("admin", "admin");

    ResourceAction datasourceR = new ResourceAction(
        new Resource(".*", ResourceType.DATASOURCE),
        Action.READ
    );

    ResourceAction datasourceW = new ResourceAction(
        new Resource(".*", ResourceType.DATASOURCE),
        Action.WRITE
    );

    ResourceAction configR = new ResourceAction(
        new Resource(".*", ResourceType.CONFIG),
        Action.READ
    );

    ResourceAction configW = new ResourceAction(
        new Resource(".*", ResourceType.CONFIG),
        Action.WRITE
    );

    ResourceAction stateR = new ResourceAction(
        new Resource(".*", ResourceType.STATE),
        Action.READ
    );

    ResourceAction stateW = new ResourceAction(
        new Resource(".*", ResourceType.STATE),
        Action.WRITE
    );

    List<ResourceAction> resActs = Lists.newArrayList(datasourceR, datasourceW, configR, configW, stateR, stateW);

    for (ResourceAction resAct : resActs) {
      try {
        byte[] serializedPermission = jsonMapper.writeValueAsBytes(resAct);
        dbConnector.addPermission("admin", serializedPermission, null);
      } catch (JsonProcessingException jpe) {
        log.error("WTF? Couldn't serialize default admin permission.");
      }
    }

    dbConnector.setUserCredentials("admin", "druid".toCharArray());

    dbConnector.createAuthenticationToAuthorizationNameMapping("admin", "admin");
  }
}
