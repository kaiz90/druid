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

package io.druid.parsers.actions;

import com.fasterxml.jackson.annotation.JacksonInject;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.base.Charsets;
import com.google.common.base.Preconditions;
import com.google.common.base.Throwables;
import io.druid.data.input.impl.ParseSpec;
import io.druid.java.util.common.CompressionUtils;
import io.druid.java.util.common.logger.Logger;
import org.apache.commons.io.IOUtils;
import org.apache.commons.io.LineIterator;
import org.jets3t.service.impl.rest.httpclient.RestS3Service;
import org.jets3t.service.model.S3Object;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;

public class S3ParseAction extends ParseAction
{
  private static final Logger log = new Logger(S3ParseAction.class);
  private static final int DEFAULT_NUM_SAMPLED_ROWS = 10;
  private static final int MAX_SAMPLED_ROWS = 100;
  private static final long MAX_BYTES_PER_ROW = 50000L;

  private final RestS3Service s3Client;
  private final List<URI> uris;
  private final int numRows;

  private List<ParserInputRow> cachedInput;

  @JsonCreator
  public S3ParseAction(
      @JacksonInject("s3Client") RestS3Service s3Client,
      @JsonProperty("parseSpec") ParseSpec parseSpec,
      @JsonProperty("uris") List<URI> uris,
      @JsonProperty("numRows") Integer numRows
  )
  {
    super(parseSpec);

    Preconditions.checkArgument(uris != null && !uris.isEmpty(), "uris cannot be null or empty");

    for (URI uri : uris) {
      Preconditions.checkArgument(
          uri.getScheme() != null && uri.getScheme().equals("s3"),
          "uri scheme == s3 (%s)",
          uri
      );
    }

    this.s3Client = s3Client;
    this.uris = uris;
    this.numRows = numRows == null ? DEFAULT_NUM_SAMPLED_ROWS : numRows;

    Preconditions.checkArgument(
        this.numRows <= MAX_SAMPLED_ROWS && this.numRows > 0,
        String.format("numRows must be 0 < x <= %d", MAX_SAMPLED_ROWS)
    );
  }

  @Override
  protected List<ParserInputRow> getInput()
  {
    if (cachedInput != null) {
      return cachedInput;
    }

    cachedInput = new ArrayList<>();

    int rowsToReadPerFile = (int) Math.ceil((double) numRows / uris.size());
    int numRowsRead = 0;
    for (URI uri : uris) {
      List<ParserInputRow> rows = getInputForUri(uri, rowsToReadPerFile);
      numRowsRead += rows.size();
      cachedInput.addAll(rows);

      if (numRowsRead >= numRows) {
        break;
      }
    }

    return cachedInput;
  }

  private List<ParserInputRow> getInputForUri(final URI uri, final int rowsToRead)
  {
    final String s3Bucket = uri.getAuthority();
    final S3Object s3Object = new S3Object(uri.getPath().startsWith("/") ? uri.getPath().substring(1) : uri.getPath());

    log.info("Reading from bucket[%s] object[%s] (%s)", s3Bucket, s3Object.getKey(), uri);

    LineIterator iterator = getS3ObjectIterator(s3Bucket, s3Object);

    List<ParserInputRow> rows = new ArrayList<>();
    int counter = 0;
    try {
      while (iterator.hasNext() && counter++ < rowsToRead) {
        rows.add(new ParserInputRow(uri.toString(), iterator.next()));
      }
    }
    finally {
      iterator.close();
    }

    return rows;
  }

  private LineIterator getS3ObjectIterator(String s3Bucket, S3Object s3Object)
  {
    try {
      final InputStream innerInputStream = s3Client
          .getObject(s3Bucket, s3Object.getKey(), null, null, null, null, 0L, numRows * MAX_BYTES_PER_ROW)
          .getDataInputStream();

      final InputStream outerInputStream = s3Object.getKey().endsWith(".gz")
                                           ? CompressionUtils.gzipInputStream(innerInputStream)
                                           : innerInputStream;

      return IOUtils.lineIterator(
          new SafetyValveReader(
              new InputStreamReader(outerInputStream, Charsets.UTF_8),
              numRows * MAX_BYTES_PER_ROW
          )
      );
    }
    catch (Exception e) {
      throw Throwables.propagate(e);
    }
  }

  public class SafetyValveReader extends Reader
  {
    private final Reader wrappedReader;
    private final long maxReadBytes;

    private long totalBytesRead = 0; // this will be approximate due to buffering

    public SafetyValveReader(Reader wrappedReader, long maxReadBytes)
    {
      this.wrappedReader = wrappedReader;
      this.maxReadBytes = maxReadBytes;
    }

    @Override
    public int read(char[] cbuf, int off, int len) throws IOException
    {
      int bytesRead = wrappedReader.read(cbuf, off, len);

      totalBytesRead += bytesRead;
      if (totalBytesRead > maxReadBytes) {
        throw new IOException(
            String.format(
                "Input maximum of [%d] bytes exceeded; make sure your rows are newline delimited",
                maxReadBytes
            )
        );
      }

      return bytesRead;
    }

    @Override
    public void close() throws IOException
    {
      wrappedReader.close();
    }
  }

  @Override
  public String toString()
  {
    return "S3ParseAction{" +
           "uris=" + uris +
           ", numRows=" + numRows +
           ", parseSpec=" + getParseSpec() +
           '}';
  }
}
