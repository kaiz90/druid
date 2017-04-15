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

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.google.common.base.Preconditions;
import io.druid.data.input.impl.ParseSpec;
import io.druid.java.util.common.logger.Logger;
import io.druid.java.util.common.parsers.ParseException;
import io.druid.java.util.common.parsers.Parser;
import io.druid.parsers.model.ParserResponse;
import io.druid.parsers.model.ParserResponseRow;
import org.jets3t.service.S3ServiceException;

import java.util.List;
import java.util.stream.Collectors;

@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, property = "type")
@JsonSubTypes(value = {
    @JsonSubTypes.Type(name = "string", value = StringParseAction.class),
    @JsonSubTypes.Type(name = "s3", value = S3ParseAction.class)
})
public abstract class ParseAction
{
  protected class ParserInputRow
  {
    private String filePath;
    private String data;

    protected ParserInputRow(String filePath, String data)
    {
      this.filePath = filePath;
      this.data = data;
    }
  }

  private static final Logger log = new Logger(ParseAction.class);

  private ParseSpec parseSpec;

  public ParseAction(ParseSpec parseSpec)
  {
    Preconditions.checkNotNull(parseSpec, "parseSpec cannot be null");

    this.parseSpec = parseSpec;
  }

  protected abstract List<ParserInputRow> getInput();

  public ParserResponse parse()
  {
    log.info(toString());

    Parser<String, Object> parser = parseSpec.makeParser();

    List<ParserInputRow> input;
    try {
      input = getInput();
    }
    catch (Exception e) {
      if (e.getCause() != null && e.getCause() instanceof S3ServiceException) {
        S3ServiceException cause = (S3ServiceException) e.getCause();
        return ParserResponse.error(cause.getS3ErrorMessage(), cause.getResponseCode());
      }

      log.warn(e, "Exception while reading");
      return ParserResponse.error(e.getMessage() != null ? e.getMessage() : "Parsing failed", null);
    }

    List<ParserResponseRow> rows = input
        .stream()
        .map(
            x -> {
              try {
                return new ParserResponseRow(x.filePath, x.data, parser.parse(x.data), null);
              }
              catch (ParseException e) {
                return new ParserResponseRow(x.filePath, x.data, null, true);
              }
            }
        )
        .collect(Collectors.toList());

    return new ParserResponse(
        rows.stream().allMatch(x -> x.isUnparseable() != null && x.isUnparseable()) ? "No rows could be parsed" : null,
        null,
        rows
    );
  }

  public ParseSpec getParseSpec()
  {
    return parseSpec;
  }
}
