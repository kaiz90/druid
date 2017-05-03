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

package io.druid.server.security.db;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Supplier;
import com.google.common.collect.ImmutableList;
import com.google.inject.Inject;
import io.druid.guice.ManageLifecycle;
import io.druid.java.util.common.logger.Logger;
import org.apache.commons.dbcp2.BasicDataSource;
import org.skife.jdbi.v2.DBI;
import org.skife.jdbi.v2.Handle;

@ManageLifecycle
public class DerbySQLSecurityStorageConnector extends SQLSecurityStorageConnector
{
  private static final Logger log = new Logger(DerbySQLSecurityStorageConnector.class);

  private final DBI dbi;
  private final DerbyAuthorizationStorage storage;
  private static final String QUOTE_STRING = "\\\"";

  @Inject
  public DerbySQLSecurityStorageConnector(
      Supplier<AuthorizationStorageConnectorConfig> config,
      ObjectMapper jsonMapper
  )
  {
    super(config, jsonMapper);

    final BasicDataSource datasource = getDatasource();
    datasource.setDriverClassLoader(getClass().getClassLoader());
    datasource.setDriverClassName("org.apache.derby.jdbc.ClientDriver");

    this.dbi = new DBI(datasource);
    this.storage = new DerbyAuthorizationStorage(config.get());
    log.info("Derby connector instantiated with auth storage [%s].", this.storage.getClass().getName());
  }

  @Override
  public void createRoleTable()
  {
    createTable(
        ROLES,
        ImmutableList.of(
            String.format(
                "CREATE TABLE %1$s (\n"
                + "  id INTEGER NOT NULL GENERATED ALWAYS AS IDENTITY (START WITH 1, INCREMENT BY 1),\n"
                + "  name VARCHAR(255) NOT NULL,\n"
                + "  PRIMARY KEY (id),\n"
                + "  UNIQUE (name)\n"
                + ")",
                ROLES
            )
        )
    );
  }

  @Override
  public void createUserTable()
  {
    createTable(
        USERS,
        ImmutableList.of(
            String.format(
                "CREATE TABLE %1$s (\n"
                + "  id INTEGER NOT NULL GENERATED ALWAYS AS IDENTITY (START WITH 1, INCREMENT BY 1),\n"
                + "  name VARCHAR(255) NOT NULL,\n"
                + "  PRIMARY KEY (id),\n"
                + "  UNIQUE (name)\n"
                + ")",
                USERS
            )
        )
    );
  }

  @Override
  public void createPermissionTable()
  {
    createTable(
        PERMISSIONS,
        ImmutableList.of(
            String.format(
                "CREATE TABLE %1$s (\n"
                + "  id INTEGER NOT NULL GENERATED ALWAYS AS IDENTITY (START WITH 1, INCREMENT BY 1),\n"
                + "  resource_json BLOB(1024) NOT NULL,\n"
                + "  role_id INTEGER NOT NULL, \n"
                + "  PRIMARY KEY (id),\n"
                + "  FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE\n"
                + ")",
                PERMISSIONS
            )
        )
    );
  }

  @Override
  public void createUserCredentialsTable()
  {
    createTable(
        USER_CREDENTIALS,
        ImmutableList.of(
            String.format(
                "CREATE TABLE %1$s (\n"
                + "  user_id INTEGER NOT NULL, \n"
                + "  salt BLOB(32) NOT NULL, \n"
                + "  hash BLOB(64) NOT NULL, \n"
                + "  iterations INTEGER NOT NULL, \n"
                + "  PRIMARY KEY (user_id), \n"
                + "  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE\n"
                + ")",
                USER_CREDENTIALS
            )
        )
    );
  }


  @Override
  public boolean tableExists(Handle handle, String tableName)
  {
    return !handle.createQuery("select * from SYS.SYSTABLES where tablename = :tableName")
                  .bind("tableName", tableName.toUpperCase())
                  .list()
                  .isEmpty();
  }

  @Override
  public String getValidationQuery() { return "VALUES 1"; }

  @Override
  public String getQuoteString() {
    return QUOTE_STRING;
  }

  @Override
  public DBI getDBI() { return dbi; }
}
