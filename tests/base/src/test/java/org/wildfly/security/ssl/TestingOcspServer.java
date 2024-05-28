/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2019 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.security.ssl;

import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import org.jboss.logging.Logger;
import org.mockserver.integration.ClientAndServer;
import org.mockserver.matchers.Times;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;
import org.wildfly.common.iteration.ByteIterator;
import org.xipki.datasource.DataSourceFactory;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.ocsp.server.servlet.OcspHttpFilter;
import org.xipki.util.http.XiHttpRequest;
import org.xipki.util.http.XiHttpResponse;

/**
 * Trivial XiPKI based OCSP server for OCSP support testing
 */
public class TestingOcspServer {

    private int port;
    private ClientAndServer server;
    private Connection connection;
    private OcspHttpFilter ocspHttpFilter;
    private static final String LICENSE_FACTORY_CLASS = "org.wildfly.security.ssl.ExampleLicenseFactory";

    private static final Logger logger =  Logger.getLogger(TestingOcspServer.class);

    public TestingOcspServer(int port) throws Exception {
        this.port = port;
        initDatabase();
        initOcspFilter();
    }

    private void initDatabase() throws Exception {
        DataSourceFactory dataSourceFactory = new DataSourceFactory();
        DataSourceWrapper dataSourceWrapper = dataSourceFactory.createDataSource("datasource1", TestingOcspServer.class.getResource("ocsp-db.properties").openStream());
        connection = dataSourceWrapper.getConnection();

        // structure described in:
        // https://github.com/xipki/xipki/blob/v6.5.3/assemblies/xipki-mgmt-cli/src/main/unfiltered/xipki/sql/liquibase/ocsp-init.xml

        connection.prepareStatement("CREATE TABLE ISSUER (\n"
                + "    ID SMALLINT PRIMARY KEY NOT NULL,\n"
                + "    SUBJECT VARCHAR(350) NOT NULL,\n"
                + "    NBEFORE BIGINT NOT NULL,\n" // notBefore of certificate, seconds since January 1, 1970, 00:00:00 GMT
                + "    NAFTER BIGINT NOT NULL,\n" // notAfter of certificate, seconds since January 1, 1970, 00:00:00 GMT
                + "    S1C CHAR(28) NOT NULL,\n" // base64 encoded SHA1 sum of the certificate
                + "    REV_INFO VARCHAR(200),\n" // CA revocation information
                + "    CERT VARCHAR(6000) NOT NULL,\n"
                + "    CRL_ID INT, \n" // CRL ID, only present for entry imported from CRL, and only if exactly one CRL is available for this CA
                + ");").execute();

        connection.prepareStatement("CREATE TABLE CERT (\n" //certificate information
                + "    ID BIGINT PRIMARY KEY NOT NULL,\n"
                + "    IID SMALLINT NOT NULL,\n" // issuer id (reference into ISSUER table)
                + "    SN VARCHAR(40) NOT NULL,\n" // serial number
                + "    CRL_ID INT,\n" //CRL ID, only present for entry imported from CRL
                + "    LUPDATE BIGINT NOT NULL,\n" // last update of the database entry, seconds since January 1, 1970, 00:00:00 GMT
                + "    NBEFORE BIGINT,\n" // notBefore of certificate, seconds since January 1, 1970, 00:00:00 GMT
                + "    NAFTER BIGINT,\n" // notAfter of certificate, seconds since January 1, 1970, 00:00:00 GMT
                + "    REV SMALLINT DEFAULT 0,\n" // whether the certificate is revoked
                + "    RR SMALLINT,\n" // revocation reason
                + "    RT BIGINT,\n" // revocation time, seconds since January 1, 1970, 00:00:00 GMT
                + "    RIT BIGINT,\n" // revocation invalidity time, seconds since January 1, 1970, 00:00:00 GMT
                + "    HASH CHAR(86),\n" //base64 encoded hash value of the DER encoded certificate. Algorithm is defined by CERTHASH_ALGO in table DBSchema
                + "    SUBJECT VARCHAR(350)" //subject of the certificate
                + ");").execute();
    }

    private void initOcspFilter() throws Exception {
        ocspHttpFilter = new OcspHttpFilter(LICENSE_FACTORY_CLASS);
        logger.info("OCSP HTTP Filter initialized successfully.");
    }

    public void start() throws Exception {
        server = new ClientAndServer(port);
        server.when(
                request()
                        .withMethod("POST")
                        .withPath("/ocsp"),
                Times.unlimited())
                .respond(this::processRequest);
        server.when(
                        request()
                                .withMethod("GET")
                                .withPath("/ocsp/.*"),
                        Times.unlimited())
                .respond(this::processRequest);
    }

    public HttpResponse processRequest(HttpRequest mockRequest) {
        try {
            XiHttpRequest xiRequest = createXiHttpRequest(mockRequest);

            XiHttpResponseImpl xiResponse = new XiHttpResponseImpl();

            ocspHttpFilter.doFilter(xiRequest, xiResponse);

            return convertToMockHttpResponse(xiResponse);

        } catch (IOException ex) {
            logger.error("Error processing OCSP request", ex);
            return response().withStatusCode(500).withBody("Internal Server Error");
        }
    }

    private XiHttpRequest createXiHttpRequest(HttpRequest mockRequest) {
        return new XiHttpRequestImpl(mockRequest);
    }

    private HttpResponse convertToMockHttpResponse(XiHttpResponseImpl xiResponse) throws IOException {
        HttpResponse mockResponse = response().withStatusCode(xiResponse.getStatus());

        // Set headers explicitly by creating Header objects
        for (String[] header : xiResponse.getHeaders()) {
            String name = header[0];
            String value = header[1];
            mockResponse.withHeader(new org.mockserver.model.Header(name, value));
        }

        // Set content
        String responseBody = xiResponse.getBody();
        if (responseBody != null) {
            mockResponse.withBody(responseBody);
        }

        return mockResponse;
    }

    public void stop() throws SQLException {
        ocspHttpFilter.destroy();
        if (server != null) {
            server.stop();
        }
        if (connection != null) {
            connection.close();
        }
    }

    public void createIssuer(int id, X509Certificate issuer) throws SQLException, CertificateException, NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-1");
        PreparedStatement statement = connection.prepareStatement("INSERT INTO ISSUER (ID, SUBJECT, NBEFORE, NAFTER, S1C, CERT) VALUES (?, ?, ?, ?, ?, ?)");
        statement.setInt(1, id);
        statement.setString(2, issuer.getSubjectDN().toString());
        statement.setLong(3, issuer.getNotBefore().toInstant().getEpochSecond());
        statement.setLong(4, issuer.getNotAfter().toInstant().getEpochSecond());
        statement.setString(5, ByteIterator.ofBytes(digest.digest(issuer.getEncoded())).base64Encode().drainToString());
        statement.setString(6, ByteIterator.ofBytes(issuer.getEncoded()).base64Encode().drainToString());
        statement.execute();
    }

    public void createCertificate(int id, int issuerId, X509Certificate certificate) throws SQLException {
        long time = Instant.now().getEpochSecond();
        PreparedStatement statement = connection.prepareStatement("INSERT INTO CERT (ID, IID, SN, LUPDATE, NBEFORE, NAFTER) VALUES (?, ?, ?, ?, ?, ?)");
        statement.setInt(1, id);
        statement.setInt(2, issuerId);
        statement.setString(3, certificate.getSerialNumber().toString(16));
        statement.setLong(4, time);
        statement.setLong(5, certificate.getNotBefore().toInstant().getEpochSecond());
        statement.setLong(6, certificate.getNotAfter().toInstant().getEpochSecond());
        statement.execute();
    }

    public void revokeCertificate(int id, int reason) throws SQLException {
        long time = Instant.now().getEpochSecond();
        PreparedStatement statement = connection.prepareStatement("UPDATE CERT SET REV = 1, RR = ?, RT = ?, RIT = ? WHERE ID = ?");
        statement.setInt(1, reason);
        statement.setLong(2, time);
        statement.setLong(3, time);
        statement.setInt(4, id);
        statement.execute();
    }

    private static class XiHttpRequestImpl implements XiHttpRequest {
        private final HttpRequest mockRequest;

        public XiHttpRequestImpl(HttpRequest mockRequest) {
            this.mockRequest = mockRequest;
        }

        @Override
        public String getHeader(String headerName) {
            return mockRequest.getFirstHeader(headerName);
        }

        @Override
        public String getParameter(String paramName) {
            // MockServer's HttpRequest doesn't directly support parameters
            return null;
        }

        @Override
        public String getMethod() {
            return mockRequest.getMethod().getValue();
        }

        @Override
        public String getServletPath() {
            return mockRequest.getPath().getValue();
        }

        @Override
        public String getContentType() {
            return mockRequest.getFirstHeader("Content-Type");
        }

        @Override
        public Object getAttribute(String name) {
            return null;
        }

        @Override
        public String getRequestURI() {
            return mockRequest.getPath().getValue();
        }

        @Override
        public InputStream getInputStream() {
            return new ByteArrayInputStream(mockRequest.getBodyAsRawBytes());
        }

        @Override
        public void setAttribute(String name, String value) {
            // No equivalent in MockServer, skip for now
        }

        @Override
        public String getContextPath() {
            return "";
        }

        @Override
        public X509Certificate[] getCertificateChain() {
            // Skip for now as MockServer doesn't have certificate handling
            return null;
        }
    }

    private static class XiHttpResponseImpl implements XiHttpResponse {
        private int status;
        private String contentType;
        private final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        private final List<String[]> headers = new ArrayList<>();

        @Override
        public void setStatus(int sc) {
            this.status = sc;
        }

        @Override
        public void sendError(int sc) throws IOException {
            this.status = sc;
            this.outputStream.write(("Error: " + sc).getBytes());
        }

        @Override
        public void setContentType(String type) {
            this.contentType = type;
        }

        @Override
        public void addHeader(String name, String value) {
            headers.add(new String[]{name, value});
        }

        @Override
        public void setHeader(String name, String value) {
            headers.removeIf(h -> h[0].equals(name)); // Remove existing
            addHeader(name, value); // Add the new one
        }

        @Override
        public void setContentLength(int len) {
            // Not necessary for MockServer, can skip
        }

        @Override
        public OutputStream getOutputStream() throws IOException {
            return outputStream;
        }

        public String getBody() throws IOException {
            outputStream.flush();
            return outputStream.toString();
        }

        public List<String[]> getHeaders() {
            return headers;
        }

        public int getStatus() {
            return status;
        }
    }
}