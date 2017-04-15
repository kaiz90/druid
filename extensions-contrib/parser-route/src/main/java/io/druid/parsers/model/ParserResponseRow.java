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

package io.druid.parsers.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Map;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class ParserResponseRow
{
  private final String filePath;
  private final String raw;
  private final Map<String, Object> parsed;
  private final Boolean unparseable;

  public ParserResponseRow(String filePath, String raw, Map<String, Object> parsed, Boolean unparseable)
  {
    this.filePath = filePath;
    this.raw = raw;
    this.parsed = parsed;
    this.unparseable = unparseable;
  }

  @JsonProperty
  public String getFilePath()
  {
    return filePath;
  }

  @JsonProperty
  public String getRaw()
  {
    return raw;
  }

  @JsonProperty
  public Map<String, Object> getParsed()
  {
    return parsed;
  }

  @JsonProperty
  public Boolean isUnparseable()
  {
    return unparseable;
  }
}
