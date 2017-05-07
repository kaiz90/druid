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

package io.druid.data.input.impl;

import com.google.common.collect.Iterators;
import io.druid.data.input.Firehose;
import io.druid.data.input.InputRow;
import io.druid.utils.Runnables;
import org.apache.commons.io.LineIterator;

import java.io.Closeable;
import java.io.IOException;
import java.util.Iterator;
import java.util.NoSuchElementException;

/**
 */
public class FileIteratingFirehose implements Firehose
{
  private static final int DEFAULT_NUM_SKIP_HEAD_ROWS = 0;

  private final Iterator<LineIterator> lineIterators;
  private final StringInputRowParser parser;
  private final int maxNumSkipHeadRows;

  private LineIterator lineIterator = null;

  private final Closeable closer;

  public FileIteratingFirehose(
      Iterator<LineIterator> lineIterators,
      StringInputRowParser parser
  )
  {
    this(lineIterators, parser, null);
  }

  public FileIteratingFirehose(
      Iterator<LineIterator> lineIterators,
      StringInputRowParser parser,
      Closeable closer
  )
  {
    this.lineIterators = lineIterators;
    this.parser = parser;
    final ParseSpec parseSpec = parser.getParseSpec();
    if (parseSpec instanceof CSVParseSpec) {
      final Integer maxNumSkipHeadRows = ((CSVParseSpec) parseSpec).getMaxNumSkipHeadRows();
      this.maxNumSkipHeadRows = maxNumSkipHeadRows == null ? DEFAULT_NUM_SKIP_HEAD_ROWS : maxNumSkipHeadRows;
    } else if (parseSpec instanceof DelimitedParseSpec) {
      final Integer maxNumSkipHeadRows = ((DelimitedParseSpec) parseSpec).getMaxNumSkipHeadRows();
      this.maxNumSkipHeadRows = maxNumSkipHeadRows == null ? DEFAULT_NUM_SKIP_HEAD_ROWS : maxNumSkipHeadRows;
    } else {
      maxNumSkipHeadRows = DEFAULT_NUM_SKIP_HEAD_ROWS;
    }
    this.closer = closer;
  }

  @Override
  public boolean hasMore()
  {
    while ((lineIterator == null || !lineIterator.hasNext()) && lineIterators.hasNext()) {
      lineIterator = getNextLineIterator();
      for (int i = 0; i < maxNumSkipHeadRows && lineIterator.hasNext(); i++) {
        lineIterator.next();
      }
    }

    return lineIterator != null && lineIterator.hasNext();
  }

  @Override
  public InputRow nextRow()
  {
    if (!hasMore()) {
      throw new NoSuchElementException();
    }

    return parser.parse(lineIterator.next());
  }

  private LineIterator getNextLineIterator()
  {
    if (lineIterator != null) {
      lineIterator.close();
    }

    return lineIterators.next();
  }

  @Override
  public Runnable commit()
  {
    return Runnables.getNoopRunnable();
  }

  @Override
  public void close() throws IOException
  {
    try {
      if (lineIterator != null) {
        lineIterator.close();
      }
    }
    catch (Throwable t) {
      try {
        if (closer != null) {
          closer.close();
        }
      }
      catch (Exception e) {
        t.addSuppressed(e);
      }
      throw t;
    }
    if (closer != null) {
      closer.close();
    }
  }
}
