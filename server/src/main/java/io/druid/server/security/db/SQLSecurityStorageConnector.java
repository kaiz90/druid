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
import com.google.common.base.Predicate;
import com.google.common.base.Supplier;
import com.google.common.base.Throwables;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.inject.Inject;
import io.druid.java.util.common.RetryUtils;
import io.druid.java.util.common.logger.Logger;
import io.druid.metadata.RetryTransactionException;
import io.druid.server.security.AuthenticationUtils;
import io.druid.server.security.ResourceAction;
import org.apache.commons.dbcp2.BasicDataSource;
import org.skife.jdbi.v2.Batch;
import org.skife.jdbi.v2.DBI;
import org.skife.jdbi.v2.Handle;
import org.skife.jdbi.v2.StatementContext;
import org.skife.jdbi.v2.TransactionCallback;
import org.skife.jdbi.v2.TransactionStatus;
import org.skife.jdbi.v2.exceptions.DBIException;
import org.skife.jdbi.v2.exceptions.UnableToExecuteStatementException;
import org.skife.jdbi.v2.exceptions.UnableToObtainConnectionException;
import org.skife.jdbi.v2.tweak.HandleCallback;
import org.skife.jdbi.v2.tweak.ResultSetMapper;
import org.skife.jdbi.v2.util.IntegerMapper;
import org.skife.jdbi.v2.util.StringMapper;

import java.io.IOException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.SQLRecoverableException;
import java.sql.SQLTransientException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;

public abstract class SQLSecurityStorageConnector implements SecurityStorageConnector
{
  private static final Logger log = new Logger(SQLSecurityStorageConnector.class);

  private static final String PAYLOAD_TYPE = "BLOB";

  public static final String AUTHENTICATION_AUTHORIZATION_NAME_MAPPINGS = "authentication_authorization_name_mappings";
  public static final String USERS = "users";
  public static final String USER_CREDENTIALS = "user_credentials";
  public static final String PERMISSIONS = "permissions";
  public static final String ROLES = "roles";
  public static final String USER_ROLES = "user_roles";

  public static final int DEFAULT_MAX_TRIES = 10;

  private final Supplier<AuthorizationStorageConnectorConfig> config;
  private final Predicate<Throwable> shouldRetry;
  private final ObjectMapper jsonMapper;
  private final PermissionsMapper permMapper;
  private final UserCredentialsMapper credsMapper;

  @Inject
  public SQLSecurityStorageConnector(
      Supplier<AuthorizationStorageConnectorConfig> config,
      ObjectMapper jsonMapper
  )
  {
    this.config = config;
    this.jsonMapper = jsonMapper;
    this.permMapper = new PermissionsMapper();
    this.credsMapper = new UserCredentialsMapper();
    this.shouldRetry = new Predicate<Throwable>()
    {
      @Override
      public boolean apply(Throwable e)
      {
        return isTransientException(e);
      }
    };
  }

  @Override
  public void createRoleTable()
  {
    createTable(
        ROLES,
        ImmutableList.of(
            String.format(
                "CREATE TABLE %1$s (\n"
                + "  id INTEGER NOT NULL,\n"
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
                + "  id INTEGER NOT NULL,\n"
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
  public void createUserCredentialsTable()
  {
    createTable(
        USER_CREDENTIALS,
        ImmutableList.of(
            String.format(
                "CREATE TABLE %1$s (\n"
                + "  user_id INTEGER NOT NULL, \n"
                + "  salt VARBINARY(32) NOT NULL, \n"
                + "  hash VARBINARY(64) NOT NULL, \n"
                + "  iterations INTEGER NOT NULL, \n"
                + "  PRIMARY KEY (user_id) REFERENCES users(id) ON DELETE CASCADE\n"
                + ")",
                USER_CREDENTIALS
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
                + "  id INTEGER NOT NULL,\n"
                + "  resource_json VARCHAR(255) NOT NULL,\n"
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
  public void createUserRoleTable()
  {
    createTable(
        USER_ROLES,
        ImmutableList.of(
            String.format(
                "CREATE TABLE %1$s (\n"
                + "  user_id INTEGER NOT NULL,\n"
                + "  role_id INTEGER NOT NULL, \n"
                + "  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,\n"
                + "  FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE\n"
                + ")",
                USER_ROLES
            )
        )
    );
  }

  @Override
  public void createAuthenticationToAuthorizationNameMappingTable()
  {
    createTable(
        AUTHENTICATION_AUTHORIZATION_NAME_MAPPINGS,
        ImmutableList.of(
            String.format(
                "CREATE TABLE %1$s (\n"
                + "  authentication_name VARCHAR(255) NOT NULL, \n"
                + "  authorization_name VARCHAR(255) NOT NULL, \n"
                + "  PRIMARY KEY (authentication_name),\n"
                + "  FOREIGN KEY (authorization_name) REFERENCES users(name) ON DELETE CASCADE\n"
                + ")",
                AUTHENTICATION_AUTHORIZATION_NAME_MAPPINGS
            )
        )
    );
  }

  @Override
  public void deleteAllRecords(String tableName)
  {
    throw new UnsupportedOperationException("delete all not supported yet for authorization storage");
  }

  // NOTE: should refactor this class to share code with the metadata SQL connector, but do that later

  public AuthorizationStorageConnectorConfig getConfig() { return config.get(); }

  protected BasicDataSource getDatasource()
  {
    AuthorizationStorageConnectorConfig connectorConfig = getConfig();

    BasicDataSource dataSource = new BasicDataSource();
    dataSource.setUsername(connectorConfig.getUser());
    dataSource.setPassword(connectorConfig.getPassword());
    String uri = connectorConfig.getConnectURI();
    dataSource.setUrl(uri);

    dataSource.setValidationQuery(getValidationQuery());
    dataSource.setTestOnBorrow(true);

    return dataSource;
  }

  protected boolean connectorIsTransientException(Throwable e)
  {
    return false;
  }

  /**
   * SQL type to use for payload data (e.g. JSON blobs).
   * Must be a binary type, which values can be accessed using ResultSet.getBytes()
   * <p/>
   * The resulting string will be interpolated into the table creation statement, e.g.
   * <code>CREATE TABLE druid_table ( payload <type> NOT NULL, ... )</code>
   *
   * @return String representing the SQL type
   */
  protected String getPayloadType()
  {
    return PAYLOAD_TYPE;
  }

  /**
   * @return the string that should be used to quote string fields
   */
  public abstract String getQuoteString();

  public abstract boolean tableExists(Handle handle, final String tableName);

  public abstract DBI getDBI();

  public String getValidationQuery() { return "SELECT 1"; }

  @Override
  public void createUser(String userName)
  {
    getDBI().inTransaction(
        new TransactionCallback<Void>()
        {
          @Override
          public Void inTransaction(Handle handle, TransactionStatus transactionStatus) throws Exception
          {
            handle.createStatement(
                String.format(
                    "INSERT INTO %1$s (name) VALUES (:user_name)", USERS
                )
            )
                  .bind("user_name", userName)
                  .execute();
            return null;
          }
        }
    );
  }

  @Override
  public void deleteUser(String userName)
  {
    getDBI().inTransaction(
        new TransactionCallback<Void>()
        {
          @Override
          public Void inTransaction(Handle handle, TransactionStatus transactionStatus) throws Exception
          {
            handle.createStatement(
                String.format(
                    "DELETE FROM %1$s WHERE name = :userName", USERS
                )
            )
                  .bind("userName", userName)
                  .execute();
            return null;
          }
        }
    );
  }

  @Override
  public void createRole(String roleName)
  {
    getDBI().inTransaction(
        new TransactionCallback<Void>()
        {
          @Override
          public Void inTransaction(Handle handle, TransactionStatus transactionStatus) throws Exception
          {
            handle.createStatement(
                String.format(
                    "INSERT INTO %1$s (name) VALUES (:roleName)", ROLES
                )
            )
                  .bind("roleName", roleName)
                  .execute();
            return null;
          }
        }
    );
  }

  @Override
  public void deleteRole(String roleName)
  {
    getDBI().inTransaction(
        new TransactionCallback<Void>()
        {
          @Override
          public Void inTransaction(Handle handle, TransactionStatus transactionStatus) throws Exception
          {
            handle.createStatement(
                String.format(
                    "DELETE FROM %1$s WHERE name = :roleName", ROLES
                )
            )
                  .bind("roleName", roleName)
                  .execute();
            return null;
          }
        }
    );
  }

  @Override
  public void addPermission(String roleName, byte[] serializedResourceIdentifier, String action)
  {
    getDBI().inTransaction(
        new TransactionCallback<Void>()
        {
          @Override
          public Void inTransaction(Handle handle, TransactionStatus transactionStatus) throws Exception
          {
            int roleId = handle
                .createQuery(
                    String.format("SELECT id FROM %1$s WHERE name = :roleName", ROLES)
                )
                .bind("roleName", roleName)
                .map(IntegerMapper.FIRST)
                .first();

            handle.createStatement(
                String.format(
                    "INSERT INTO %1$s (resource_json, role_id) VALUES (:resourceJson, :roleId)",
                    PERMISSIONS
                )
            )
                  .bind("resourceJson", serializedResourceIdentifier)
                  .bind("roleId", roleId)
                  .execute();

            return null;
          }
        }
    );
  }

  @Override
  public void deleteAllPermissionsFromRole(String roleName)
  {
    getDBI().inTransaction(
        new TransactionCallback<Void>()
        {
          @Override
          public Void inTransaction(Handle handle, TransactionStatus transactionStatus) throws Exception
          {
            int roleId = handle
                .createQuery(
                    String.format("SELECT id FROM %1$s WHERE name = :roleName", ROLES)
                )
                .bind("roleName", roleName)
                .map(IntegerMapper.FIRST)
                .first();

            handle.createStatement(
                String.format(
                    "DELETE FROM %1$s WHERE role_id = :roleId",
                    PERMISSIONS
                )
            )
                  .bind("roleId", roleId)
                  .execute();

            return null;
          }
        }
    );
  }

  @Override
  public void deletePermission(int permissionId)
  {
    getDBI().inTransaction(
        new TransactionCallback<Void>()
        {
          @Override
          public Void inTransaction(Handle handle, TransactionStatus transactionStatus) throws Exception
          {
            handle.createStatement(
                String.format(
                    "DELETE FROM %1$s WHERE id = :permissionId", PERMISSIONS
                )
            )
                  .bind("permissionId", permissionId)
                  .execute();
            return null;
          }
        }
    );
  }

  @Override
  public void assignRole(String userName, String roleName)
  {
    getDBI().inTransaction(
        new TransactionCallback<Void>()
        {
          @Override
          public Void inTransaction(Handle handle, TransactionStatus transactionStatus) throws Exception
          {
            int roleId = handle
                .createQuery(
                    String.format("SELECT id FROM %1$s WHERE name = :roleName", ROLES)
                )
                .bind("roleName", roleName)
                .map(IntegerMapper.FIRST)
                .first();

            int userId = handle
                .createQuery(
                    String.format("SELECT id FROM %1$s WHERE name = :userName", USERS)
                )
                .bind("userName", userName)
                .map(IntegerMapper.FIRST)
                .first();

            handle.createStatement(
                String.format(
                    "INSERT INTO %1$s (user_id, role_id) VALUES (:userId, :roleId)", USER_ROLES
                )
            )
                  .bind("userId", userId)
                  .bind("roleId", roleId)
                  .execute();
            return null;
          }
        }
    );
  }

  @Override
  public void unassignRole(String userName, String roleName)
  {
    getDBI().inTransaction(
        new TransactionCallback<Void>()
        {
          @Override
          public Void inTransaction(Handle handle, TransactionStatus transactionStatus) throws Exception
          {
            int roleId = handle
                .createQuery(
                    String.format("SELECT id FROM %1$s WHERE name = :roleName", ROLES)
                )
                .bind("roleName", roleName)
                .map(IntegerMapper.FIRST)
                .first();

            int userId = handle
                .createQuery(
                    String.format("SELECT id FROM %1$s WHERE name = :userName", USERS)
                )
                .bind("userName", userName)
                .map(IntegerMapper.FIRST)
                .first();

            handle.createStatement(
                String.format(
                    "DELETE FROM %1$s WHERE user_id = :userId AND role_id = :roleId", USER_ROLES
                )
            )
                  .bind("userId", userId)
                  .bind("roleId", roleId)
                  .execute();

            return null;
          }
        }
    );
  }

  @Override
  public List<Map<String, Object>> getAllUsers()
  {
    return getDBI().inTransaction(
        new TransactionCallback<List<Map<String, Object>>>()
        {
          @Override
          public List<Map<String, Object>> inTransaction(Handle handle, TransactionStatus transactionStatus) throws Exception
          {
            return handle
                .createQuery(
                    String.format("SELECT * FROM users")
                )
                .list();
          }
        }
    );
  }

  @Override
  public List<Map<String, Object>> getAllRoles()
  {
    return getDBI().inTransaction(
        new TransactionCallback<List<Map<String, Object>>>()
        {
          @Override
          public List<Map<String, Object>> inTransaction(Handle handle, TransactionStatus transactionStatus) throws Exception
          {
            return handle
                .createQuery(
                    String.format("SELECT * FROM roles")
                )
                .list();
          }
        }
    );
  }

  @Override
  public Map<String, Object> getUser(String userName)
  {
    return getDBI().inTransaction(
        new TransactionCallback<Map<String, Object>>()
        {
          @Override
          public Map<String, Object> inTransaction(Handle handle, TransactionStatus transactionStatus) throws Exception
          {
            return handle
                .createQuery(
                    String.format("SELECT * FROM users where name = :userName")
                )
                .bind("userName", userName)
                .first();
          }
        }
    );
  }

  @Override
  public Map<String, Object> getRole(String roleName)
  {
    return getDBI().inTransaction(
        new TransactionCallback<Map<String, Object>>()
        {
          @Override
          public Map<String, Object> inTransaction(Handle handle, TransactionStatus transactionStatus) throws Exception
          {
            return handle
                .createQuery(
                    String.format("SELECT * FROM roles where name = :roleName")
                )
                .bind("roleName", roleName)
                .first();
          }
        }
    );
  }

  @Override
  public List<Map<String, Object>> getRolesForUser(String userName)
  {
    return getDBI().inTransaction(
        new TransactionCallback<List<Map<String, Object>>>()
        {
          @Override
          public List<Map<String, Object>> inTransaction(Handle handle, TransactionStatus transactionStatus) throws Exception
          {
            int userId = handle
                .createQuery(
                    String.format("SELECT id FROM %1$s WHERE name = :userName", USERS)
                )
                .bind("userName", userName)
                .map(IntegerMapper.FIRST)
                .first();

            List<Map<String, Object>> user_roles = handle
                .createQuery(
                    String.format(
                        "SELECT roles.id, roles.name\n"
                        + "FROM roles\n"
                        + "JOIN user_roles\n"
                        + "    ON user_roles.role_id = roles.id\n"
                        + "WHERE user_roles.user_id = :userId"
                    )
                )
                .bind("userId", userId)
                .list();
            return user_roles;
          }
        }
    );
  }

  @Override
  public List<Map<String, Object>> getUsersWithRole(String roleName)
  {
    return getDBI().inTransaction(
        new TransactionCallback<List<Map<String, Object>>>()
        {
          @Override
          public List<Map<String, Object>> inTransaction(Handle handle, TransactionStatus transactionStatus) throws Exception
          {
            int roleId = handle
                .createQuery(
                    String.format("SELECT id FROM %1$s WHERE name = :roleName", ROLES)
                )
                .bind("roleName", roleName)
                .map(IntegerMapper.FIRST)
                .first();

            List<Map<String, Object>> user_roles = handle
                .createQuery(
                    String.format(
                        "SELECT users.id, users.name\n"
                        + "FROM users\n"
                        + "JOIN user_roles\n"
                        + "    ON user_roles.user_id = users.id\n"
                        + "WHERE user_roles.role_id = :roleId"
                    )
                )
                .bind("roleId", roleId)
                .list();
            return user_roles;
          }
        }
    );
  }

  private class PermissionsMapper implements ResultSetMapper<Map<String, Object>>
  {
    @Override
    public Map<String, Object> map(int index, ResultSet resultSet, StatementContext context)
        throws SQLException {

      int id = resultSet.getInt("id");
      byte[] resourceJson = resultSet.getBytes("resource_json");
      try {
        final ResourceAction resourceAction = jsonMapper.readValue(resourceJson, ResourceAction.class);
        return ImmutableMap.of(
            "id", id,
            "resourceAction", resourceAction
        );
      } catch (IOException ioe) {
        return null;
      }
    }
  }

  @Override
  public List<Map<String, Object>> getPermissionsForRole(String roleName)
  {
    return getDBI().inTransaction(
        new TransactionCallback<List<Map<String, Object>>>()
        {
          @Override
          public List<Map<String, Object>> inTransaction(Handle handle, TransactionStatus transactionStatus) throws Exception
          {
            int roleId = handle
                .createQuery(
                    String.format("SELECT id FROM %1$s WHERE name = :roleName", ROLES)
                )
                .bind("roleName", roleName)
                .map(IntegerMapper.FIRST)
                .first();

            List<Map<String, Object>> role_permissions = handle
                .createQuery(
                    String.format(
                        "SELECT permissions.id, permissions.resource_json\n"
                        + "FROM permissions\n"
                        + "WHERE permissions.role_id = :roleId"
                    )
                )
                .map(permMapper)
                .bind("roleId", roleId)
                .list();
            return role_permissions;
          }
        }
    );
  }

  @Override
  public List<Map<String, Object>> getPermissionsForUser(String userName)
  {
    return getDBI().inTransaction(
        new TransactionCallback<List<Map<String, Object>>>()
        {
          @Override
          public List<Map<String, Object>> inTransaction(Handle handle, TransactionStatus transactionStatus) throws Exception
          {
            int userId = handle
                .createQuery(
                    String.format("SELECT id FROM %1$s WHERE name = :userName", USERS)
                )
                .bind("userName", userName)
                .map(IntegerMapper.FIRST)
                .first();

            List<Map<String, Object>> user_permissions = handle
                .createQuery(
                    String.format(
                        "SELECT permissions.id, permissions.resource_json, roles.id\n"
                        + "FROM permissions\n"
                        + "JOIN roles\n"
                        + "    ON permissions.role_id = roles.id\n"
                        + "JOIN user_roles\n"
                        + "    ON user_roles.role_id = roles.id\n"
                        + "WHERE user_roles.user_id = :userId"
                    )
                )
                .map(permMapper)
                .bind("userId", userId)
                .list();
            return user_permissions;
          }
        }
    );
  }

  @Override
  public void createAuthenticationToAuthorizationNameMapping(
      String authenticationName, String authorizationName
  )
  {
    getDBI().inTransaction(
        new TransactionCallback<Void>()
        {
          @Override
          public Void inTransaction(Handle handle, TransactionStatus transactionStatus) throws Exception
          {
            String existingMapping = handle
                .createQuery(
                    String.format("SELECT authorization_name FROM %1$s WHERE authentication_name = :authenticationName",
                                  AUTHENTICATION_AUTHORIZATION_NAME_MAPPINGS)
                )
                .bind("authenticationName", authenticationName)
                .map(StringMapper.FIRST)
                .first();

            if (existingMapping == null) {
              handle.createStatement(
                  String.format(
                      "INSERT INTO %1$s (authentication_name, authorization_name) VALUES (:authenticationName, :authorizationName)",
                      AUTHENTICATION_AUTHORIZATION_NAME_MAPPINGS
                  )
              )
                    .bind("authenticationName", authenticationName)
                    .bind("authorizationName", authorizationName)
                    .execute();
            } else {
              handle.createStatement(
                  String.format(
                      "UPDATE %1$s SET authorization_name = :authorizationName " +
                      "WHERE authentication_name = :authenticationName",
                      AUTHENTICATION_AUTHORIZATION_NAME_MAPPINGS
                  )
              )
                    .bind("authenticationName", authenticationName)
                    .bind("authorizationName", authorizationName)
                    .execute();
            }

            return null;
          }
        }
    );
  }

  @Override
  public String getAuthorizationNameFromAuthenticationName(String authenticationName)
  {
     return getDBI().inTransaction(
        new TransactionCallback<String>()
        {
          @Override
          public String inTransaction(Handle handle, TransactionStatus transactionStatus) throws Exception
          {
            return handle
                .createQuery(
                    String.format(
                        "SELECT authorization_name FROM %1$s WHERE authentication_name = :authenticationName",
                        AUTHENTICATION_AUTHORIZATION_NAME_MAPPINGS
                    )
                )
                .bind("authenticationName", authenticationName)
                .map(StringMapper.FIRST)
                .first();
          }
        }
    );
  }

  @Override
  public void deleteAuthenticationToAuthorizationNameMapping(String authenticationName)
  {
    getDBI().inTransaction(
        new TransactionCallback<Void>()
        {
          @Override
          public Void inTransaction(Handle handle, TransactionStatus transactionStatus) throws Exception
          {
            handle.createStatement(
                String.format(
                    "DELETE FROM %1$s WHERE authentication_name = :authenticationName",
                    AUTHENTICATION_AUTHORIZATION_NAME_MAPPINGS
                )
            )
                  .bind("authenticationName", authenticationName)
                  .execute();
            return null;
          }
        }
    );
  }

  private static class UserCredentialsMapper implements ResultSetMapper<Map<String, Object>>
  {
    @Override
    public Map<String, Object> map(int index, ResultSet resultSet, StatementContext context)
        throws SQLException
    {

      int user_id = resultSet.getInt("user_id");
      byte[] salt = resultSet.getBytes("salt");
      byte[] hash = resultSet.getBytes("hash");
      int iterations = resultSet.getInt("iterations");
      return ImmutableMap.of(
          "user_id", user_id,
          "salt", salt,
          "hash", hash,
          "iterations", iterations
      );
    }
  }


  @Override
  public Map<String, Object> getUserCredentials(String userName)
  {
    return getDBI().inTransaction(
        new TransactionCallback<Map<String, Object>>()
        {
          @Override
          public Map<String, Object> inTransaction(Handle handle, TransactionStatus transactionStatus) throws Exception
          {
            int userId = handle
                .createQuery(
                    String.format("SELECT id FROM %1$s WHERE name = :userName", USERS)
                )
                .bind("userName", userName)
                .map(IntegerMapper.FIRST)
                .first();

            return handle
                .createQuery(
                    String.format("SELECT * FROM %1$s where user_id = :userId", USER_CREDENTIALS)
                )
                .map(credsMapper)
                .bind("userId", userId)
                .first();
          }
        }
    );
  }

  @Override
  public void setUserCredentials(String userName, char[] password)
  {
    getDBI().inTransaction(
        new TransactionCallback<Void>()
        {
          @Override
          public Void inTransaction(Handle handle, TransactionStatus transactionStatus) throws Exception
          {
            int userId = handle
                .createQuery(
                    String.format("SELECT id FROM %1$s WHERE name = :userName", USERS)
                )
                .bind("userName", userName)
                .map(IntegerMapper.FIRST)
                .first();

            Map<String, Object> existingMapping = handle
                .createQuery(
                    String.format("SELECT user_id FROM %1$s WHERE user_id = :userId",
                                  USER_CREDENTIALS)
                )
                .bind("userId", userId)
                .first();

            int iterations = AuthenticationUtils.KEY_ITERATIONS;
            byte[] salt = AuthenticationUtils.generateSalt();
            byte[] hash = AuthenticationUtils.hashPassword(password, salt, iterations);

            if (existingMapping == null) {
              handle.createStatement(
                  String.format(
                      "INSERT INTO %1$s (user_id, salt, hash, iterations) " +
                      "VALUES (:userId, :salt, :hash, :iterations)",
                      USER_CREDENTIALS
                  )
              )
                    .bind("userId", userId)
                    .bind("salt", salt)
                    .bind("hash", hash)
                    .bind("iterations", iterations)
                    .execute();
            } else {
              handle.createStatement(
                  String.format(
                      "UPDATE %1$s SET " +
                      "salt = :salt, " +
                      "hash = :hash, " +
                      "iterations = :iterations " +
                      "WHERE user_id = :userId",
                      USER_CREDENTIALS
                  )
              )
                    .bind("userId", userId)
                    .bind("salt", salt)
                    .bind("hash", hash)
                    .bind("iterations", iterations)
                    .execute();
            }

            return null;
          }
        }
    );
  }

  @Override
  public boolean checkCredentials(String userName, char[] password)
  {
    return getDBI().inTransaction(
        new TransactionCallback<Boolean>()
        {
          @Override
          public Boolean inTransaction(Handle handle, TransactionStatus transactionStatus) throws Exception
          {
            Integer userId = handle
                .createQuery(
                    String.format("SELECT id FROM %1$s WHERE name = :userName", USERS)
                )
                .bind("userName", userName)
                .map(IntegerMapper.FIRST)
                .first();

            if (userId == null) {
              return false;
            }

            Map<String, Object> credentials = handle
                .createQuery(
                    String.format("SELECT * FROM %1$s WHERE user_id = :userId",
                                  USER_CREDENTIALS)
                )
                .bind("userId", userId)
                .map(credsMapper)
                .first();

            if (credentials == null) {
              return false;
            }

            byte[] dbSalt = (byte[]) credentials.get("salt");
            byte[] dbHash = (byte[]) credentials.get("hash");
            int iterations = (int) credentials.get("iterations");

            byte[] hash = AuthenticationUtils.hashPassword(password, dbSalt, iterations);

            return Arrays.equals(dbHash, hash);
          }
        }
    );
  }

  public final boolean isTransientException(Throwable e)
  {
    return e != null && (e instanceof RetryTransactionException
                         || e instanceof SQLTransientException
                         || e instanceof SQLRecoverableException
                         || e instanceof UnableToObtainConnectionException
                         || e instanceof UnableToExecuteStatementException
                         || connectorIsTransientException(e)
                         || (e instanceof SQLException && isTransientException(e.getCause()))
                         || (e instanceof DBIException && isTransientException(e.getCause())));
  }

  public void createTable(final String tableName, final Iterable<String> sql)
  {
    if (!config.get().isCreateTables()) {
      return;
    }

    try {
      retryWithHandle(
          new HandleCallback<Void>()
          {
            @Override
            public Void withHandle(Handle handle) throws Exception
            {
              if (!tableExists(handle, tableName)) {
                log.info("Creating table[%s]", tableName);
                final Batch batch = handle.createBatch();
                for (String s : sql) {
                  batch.add(s);
                }
                batch.execute();
              } else {
                log.info("Table[%s] already exists", tableName);
              }
              return null;
            }
          }
      );
    }
    catch (Exception e) {
      log.warn(e, "Exception creating table");
    }
  }

  public <T> T retryWithHandle(
      final HandleCallback<T> callback,
      final Predicate<Throwable> myShouldRetry
  )
  {
    final Callable<T> call = new Callable<T>()
    {
      @Override
      public T call() throws Exception
      {
        return getDBI().withHandle(callback);
      }
    };
    try {
      return RetryUtils.retry(call, myShouldRetry, DEFAULT_MAX_TRIES);
    }
    catch (Exception e) {
      throw Throwables.propagate(e);
    }
  }

  public <T> T retryWithHandle(final HandleCallback<T> callback)
  {
    return retryWithHandle(callback, shouldRetry);
  }

  public <T> T retryTransaction(final TransactionCallback<T> callback, final int quietTries, final int maxTries)
  {
    final Callable<T> call = new Callable<T>()
    {
      @Override
      public T call() throws Exception
      {
        return getDBI().inTransaction(callback);
      }
    };
    try {
      return RetryUtils.retry(call, shouldRetry, quietTries, maxTries);
    }
    catch (Exception e) {
      throw Throwables.propagate(e);
    }
  }
}
