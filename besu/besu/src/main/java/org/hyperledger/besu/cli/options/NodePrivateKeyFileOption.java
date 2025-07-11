/*
 * Copyright contributors to Hyperledger Besu.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package org.hyperledger.besu.cli.options;

import static org.hyperledger.besu.cli.DefaultCommandValues.MANDATORY_PATH_FORMAT_HELP;

import java.io.File;

import picocli.CommandLine;

/** The Node private key file Cli option. */
public class NodePrivateKeyFileOption {
  /** Default constructor. */
  NodePrivateKeyFileOption() {}

  /**
   * Create node private key file option.
   *
   * @return the node private key file option
   */
  public static NodePrivateKeyFileOption create() {
    return new NodePrivateKeyFileOption();
  }

  @CommandLine.Option(
      names = {"--node-private-key-file"},
      paramLabel = MANDATORY_PATH_FORMAT_HELP,
      description =
          "The node's private key file (default: a file named \"key\" in the Besu data directory)")
  private final File nodePrivateKeyFile = null;

  // NEW ROUTINE FOR DOUBLE SIGNING
  @CommandLine.Option(
      names = {"--node-private-key-file2"},
      paramLabel = MANDATORY_PATH_FORMAT_HELP,
      description = "Second private key file for a dual-signing Clique node")
  private final File nodePrivateKeyFile2 = null;

  /**
   * Gets node private key file.
   *
   * @return the node private key file
   */
  public File getNodePrivateKeyFile() {
    return nodePrivateKeyFile;
  }

  /**
   * Gets node private key file 2.
   *
   * @return the node private key file
   */
  public File getNodePrivateKeyFile2() {
    return nodePrivateKeyFile2;
  }
}
