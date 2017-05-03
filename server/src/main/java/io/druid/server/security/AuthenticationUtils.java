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

import com.amazonaws.util.Base64;
import com.google.inject.Injector;
import io.druid.java.util.common.logger.Logger;
import org.eclipse.jetty.servlet.FilterHolder;
import org.eclipse.jetty.servlet.ServletContextHandler;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.servlet.http.HttpServletRequest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

public class AuthenticationUtils
{
  private static final Logger log = new Logger(AuthenticationUtils.class);

  public static int SALT_LENGTH = 32;
  public static int KEY_ITERATIONS = 10000;
  public static int KEY_LENGTH = 64;
  public static String ALGORITHM = "PBKDF2WithHmacSHA512";

  public static byte[] hashPassword(final char[] password, final byte[] salt, final int iterations)
  {
    try {
      SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(ALGORITHM);
      SecretKey key = keyFactory.generateSecret(
          new PBEKeySpec(
              password,
              salt,
              iterations,
              KEY_LENGTH
          )
      );
      return key.getEncoded();
    } catch (InvalidKeySpecException ikse) {
      log.error("WTF? invalid keyspec");
      throw new RuntimeException(ikse);
    } catch (NoSuchAlgorithmException nsae) {
      log.error("%s not supported on this system.", ALGORITHM);
      throw new RuntimeException(nsae );
    }
  }

  public static byte[] generateSalt()
  {
    SecureRandom secureRandom = new SecureRandom();
    byte salt[] = new byte[SALT_LENGTH];
    secureRandom.nextBytes(salt);
    return salt;
  }

  public static void addBasicAuthenticationFilter(ServletContextHandler root, Injector injector)
  {
    BasicAuthenticationServletFilterHolder.BasicAuthenticationFilter filter =
        new BasicAuthenticationServletFilterHolder.BasicAuthenticationFilter(injector);

    root.addFilter(
        new FilterHolder(filter),
        "/*",
        null
    );
  }

  public static void addPreResponseAuthorizationCheckFilter(ServletContextHandler root, Injector injector)
  {
    PreResponseAuthorizationCheckFilterHolder holder = injector.getInstance(
        PreResponseAuthorizationCheckFilterHolder.class
    );

    root.addFilter(new FilterHolder(holder.getFilter()), "/*", null);
  }

  public static String getBasicUserSecretFromHttpReq(HttpServletRequest httpReq) {
    try {
      String authHeader = httpReq.getHeader("Authorization");

      if (authHeader == null) {
        return null;
      }

      if (!authHeader.substring(0, 6).equals("Basic ")) {
        return null;
      }

      String encodedUserSecret = authHeader.substring(6);
      return new String(Base64.decode(encodedUserSecret));
    } catch (Exception e) {
      return null;
    }
  }

  public static String buildHttpBasicAuthHeader(String user, String password) {
    String val = "Basic ";
    String userSecret = String.format("%s:%s", user, password);
    return val + Base64.encodeAsString(userSecret.getBytes());
  }
}
