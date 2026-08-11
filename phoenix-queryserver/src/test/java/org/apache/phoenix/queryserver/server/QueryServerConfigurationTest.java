/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.phoenix.queryserver.server;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;

import org.apache.calcite.avatica.server.AvaticaServerConfiguration;
import org.apache.calcite.avatica.server.DoAsRemoteUserCallback;
import org.apache.calcite.avatica.server.HttpServer;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hbase.HBaseConfiguration;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.security.alias.CredentialProvider;
import org.apache.hadoop.security.alias.CredentialProviderFactory;
import org.apache.phoenix.queryserver.QueryServerOptions;
import org.apache.phoenix.queryserver.QueryServerProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.Test;

public class QueryServerConfigurationTest {
  private static final Configuration CONF = HBaseConfiguration.create();

  @TempDir
  public Path testFolder;

  private HttpServer.Builder builder;
  private QueryServer queryServer;
  private UserGroupInformation ugi;

  @BeforeEach
  public void setup() throws IOException {
    builder = mock(HttpServer.Builder.class);
    queryServer = new QueryServer(new String[0], CONF);
    ugi = queryServer.getUserGroupInformation();
  }

  @Test
  public void testSpnegoEnabled() throws IOException {
    setupKeytabForSpnego();
    // SPENEGO settings will be provided to the builder when enabled
    doReturn(builder).when(builder).withSpnego(anyString(), nullable(String[].class));
    configureAndVerifyImpersonation(builder, false);
    // A keytab file will also be provided for automatic login
    verify(builder).withAutomaticLogin(any(File.class));
    verify(builder, never()).withCustomAuthentication(any(AvaticaServerConfiguration.class));
  }

  @Test
  public void testSpnegoDisabled() throws IOException {
    setupKeytabForSpnego();
    configureAndVerifyImpersonation(builder, true);
    verify(builder, never()).withSpnego(anyString(), any(String[].class));
    verify(builder, never()).withAutomaticLogin(any(File.class));
    verify(builder, never()).withCustomAuthentication(any(AvaticaServerConfiguration.class));
  }

  @Test
  public void testCustomServerConfiguration() {
    queryServer.enableCustomAuth(builder, CONF, ugi);
    verify(builder).withCustomAuthentication(nullable(AvaticaServerConfiguration.class));
    verify(builder, never()).withSpnego(anyString(), nullable(String[].class));
    verify(builder, never()).withAutomaticLogin(any(File.class));
    verify(builder, never()).withImpersonation(any(DoAsRemoteUserCallback.class));
  }

  @Test
  public void testTlsPasswordsResolvedFromCredentialProvider() throws Exception {
    File jceks = new File(testFolder.toFile(), "pqs.jceks");
    Configuration conf = HBaseConfiguration.create();
    conf.set(CredentialProviderFactory.CREDENTIAL_PROVIDER_PATH,
            "jceks://" + jceks.getAbsolutePath());

    CredentialProvider provider = CredentialProviderFactory.getProviders(conf).get(0);
    provider.createCredentialEntry(
            QueryServerProperties.QUERY_SERVER_TLS_KEYSTORE_PASSWORD, "ksSecret".toCharArray());
    provider.createCredentialEntry(
            QueryServerProperties.QUERY_SERVER_TLS_TRUSTSTORE_PASSWORD, "tsSecret".toCharArray());
    provider.flush();

    conf.setBoolean(QueryServerProperties.QUERY_SERVER_TLS_ENABLED, true);
    conf.set(QueryServerProperties.QUERY_SERVER_TLS_KEYSTORE, jceks.getAbsolutePath());
    conf.set(QueryServerProperties.QUERY_SERVER_TLS_TRUSTSTORE, jceks.getAbsolutePath());

    QueryServer qs = new QueryServer(new String[0], conf);
    qs.setTlsIfNeccessary(builder, conf);

    verify(builder).withTLS(
            any(File.class), eq("ksSecret"),
            any(File.class), eq("tsSecret"),
            anyString(),
            nullable(String[].class),
            nullable(String[].class));
  }

  @Test
  public void testTlsPasswordsFallBackToPlaintextConfig() throws Exception {
    File dummy = new File(testFolder.toFile(), "dummy.jsk");
    Configuration conf = HBaseConfiguration.create();

    conf.setBoolean(QueryServerProperties.QUERY_SERVER_TLS_ENABLED, true);
    conf.set(QueryServerProperties.QUERY_SERVER_TLS_KEYSTORE, dummy.getAbsolutePath());
    conf.set(QueryServerProperties.QUERY_SERVER_TLS_TRUSTSTORE, dummy.getAbsolutePath());
    conf.set(QueryServerProperties.QUERY_SERVER_TLS_KEYSTORE_PASSWORD, "ksPlain");
    conf.set(QueryServerProperties.QUERY_SERVER_TLS_TRUSTSTORE_PASSWORD, "tsPlain");

    QueryServer qs = new QueryServer(new String[0], conf);
    qs.setTlsIfNeccessary(builder, conf);

    verify(builder).withTLS(
            any(File.class), eq("ksPlain"),
            any(File.class), eq("tsPlain"),
            anyString(), nullable(String[].class), nullable(String[].class));
  }

  @Test
  public void testTlsPasswordsUseDefaultsWhenNoProvider() throws Exception {
    File dummyStore = new File(testFolder.toFile(), "dummy.keystore");
    Configuration conf = HBaseConfiguration.create();

    conf.setBoolean(QueryServerProperties.QUERY_SERVER_TLS_ENABLED, true);
    conf.set(QueryServerProperties.QUERY_SERVER_TLS_KEYSTORE,   dummyStore.getAbsolutePath());
    conf.set(QueryServerProperties.QUERY_SERVER_TLS_TRUSTSTORE, dummyStore.getAbsolutePath());

    QueryServer qs = new QueryServer(new String[0], conf);
    qs.setTlsIfNeccessary(builder, conf);

    verify(builder).withTLS(
            any(File.class), eq(QueryServerOptions.DEFAULT_QUERY_SERVER_TLS_KEYSTORE_PASSWORD),
            any(File.class), eq(QueryServerOptions.DEFAULT_QUERY_SERVER_TLS_TRUSTSTORE_PASSWORD),
            anyString(), nullable(String[].class), nullable(String[].class));
  }

  private void setupKeytabForSpnego() throws IOException {
    File keytabFile = testFolder.resolve("test.keytab").toFile();
    CONF.set(QueryServerProperties.QUERY_SERVER_KEYTAB_FILENAME_ATTRIB, keytabFile.getAbsolutePath());
  }

  private void configureAndVerifyImpersonation(HttpServer.Builder builder, boolean disableSpnego)
      throws IOException {
    queryServer.configureClientAuthentication(builder, disableSpnego, ugi);
    verify(builder).withImpersonation(any(DoAsRemoteUserCallback.class));
  }
}
