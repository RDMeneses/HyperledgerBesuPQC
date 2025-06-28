/*
 * Copyright ConsenSys AG.
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
package org.hyperledger.besu.consensus.clique;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import org.hyperledger.besu.crypto.SECPSignature;
import org.hyperledger.besu.crypto.SignatureAlgorithmFactory;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.ethereum.core.BlockHeader;
import org.hyperledger.besu.ethereum.core.ParsedExtraData;

import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;

import com.google.common.base.Suppliers;
import com.google.common.collect.Lists;
import org.apache.tuweni.bytes.Bytes;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Represents the data structure stored in the extraData field of the BlockHeader used when
 * operating under an Clique consensus mechanism.
 */
public class CliqueExtraData implements ParsedExtraData {
  private static final Logger LOG = LoggerFactory.getLogger(CliqueExtraData.class);

  /** The constant EXTRA_VANITY_LENGTH. */
  public static final int EXTRA_VANITY_LENGTH = 32;

  private final Bytes vanityData;
  private final List<Address> validators;
  private final Optional<SECPSignature> proposerSeal1;
  private final Optional<SECPSignature> proposerSeal2;
  private final Supplier<Address> proposerAddress1;
  private final Supplier<Address> proposerAddress2;

  /**
   * Instantiates a new Clique extra data.
   *
   * @param vanityData the vanity data
   * @param proposerSeal1 the proposer seal 1
   * @param proposerSeal2 the proposer seal 2
   * @param validators the validators
   * @param header the header
   */
  public CliqueExtraData(
      final Bytes vanityData,
      final SECPSignature proposerSeal1,
      final SECPSignature proposerSeal2,
      final List<Address> validators,
      final BlockHeader header) {

    checkNotNull(vanityData);
    checkNotNull(validators);
    checkNotNull(header);
    checkArgument(vanityData.size() == EXTRA_VANITY_LENGTH);

    this.vanityData = vanityData;
    this.proposerSeal1 = Optional.ofNullable(proposerSeal1);
    this.proposerSeal2 = Optional.ofNullable(proposerSeal2);
    this.validators = validators;
    proposerAddress1 =
        Suppliers.memoize(() -> CliqueBlockHashing.recoverProposerAddress(header, this, 1));
    proposerAddress2 =
        Suppliers.memoize(() -> CliqueBlockHashing.recoverProposerAddress(header, this, 2));
  }

  /**
   * Create without proposer seal.
   *
   * @param vanityData the vanity data
   * @param validators the validators
   * @return the bytes
   */
  public static Bytes createWithoutProposerSeal(
      final Bytes vanityData, final List<Address> validators) {
    // produces 32 + validators + 130 zero bytes
    return Bytes.concatenate(
        vanityData,
        Bytes.concatenate(validators.toArray(new Bytes[0])),
        Bytes.wrap(new byte[2 * SECPSignature.BYTES_REQUIRED]));
  }

  /**
   * Decode header to get clique extra data.
   *
   * @param header the header
   * @return the clique extra data
   */
  public static CliqueExtraData decode(final BlockHeader header) {
    final Object inputExtraData = header.getParsedExtraData();
    if (inputExtraData instanceof CliqueExtraData) {
      return (CliqueExtraData) inputExtraData;
    }
    LOG.warn(
        "Expected a CliqueExtraData instance but got {}. Reparsing required.",
        inputExtraData != null ? inputExtraData.getClass().getName() : "null");
    return decodeRaw(header);
  }

  /**
   * Decode raw to get clique extra data.
   *
   * @param header the header
   * @return the clique extra data
   */
  static CliqueExtraData decodeRaw(final BlockHeader header) {
    final Bytes input = header.getExtraData();
    if (input.size() < EXTRA_VANITY_LENGTH + 2 * SECPSignature.BYTES_REQUIRED) {
      throw new IllegalArgumentException(
          "Invalid Bytes supplied - too short to produce a valid Clique Extra Data object.");
    }

    final int validatorByteCount =
        input.size() - EXTRA_VANITY_LENGTH - 2 * SECPSignature.BYTES_REQUIRED;
    if ((validatorByteCount % Address.SIZE) != 0) {
      throw new IllegalArgumentException("Bytes is of invalid size - i.e. contains unused bytes.");
    }

    final Bytes vanityData = input.slice(0, EXTRA_VANITY_LENGTH);
    final List<Address> validators =
        extractValidators(input.slice(EXTRA_VANITY_LENGTH, validatorByteCount));

    // There are now 130 bytes of seal data (2 × 65)
    final int sealBytes = SECPSignature.BYTES_REQUIRED;
    final int start1 = input.size() - (2 * sealBytes);
    final int start2 = input.size() - sealBytes;

    final SECPSignature proposerSeal1 = parseProposerSeal(input.slice(start1, sealBytes));
    final SECPSignature proposerSeal2 = parseProposerSeal(input.slice(start2, sealBytes));

    return new CliqueExtraData(vanityData, proposerSeal1, proposerSeal2, validators, header);
  }

  /**
   * Gets proposer address.
   *
   * @return the proposer address
   */
  public synchronized Address getProposerAddress1() {
    return proposerAddress1.get();
  }

  /**
   * Get the address recovered from the second proposer seal.
   *
   * @return the second proposer’s, if present
   */
  public synchronized Address getProposerAddress2() {
    return proposerAddress2.get();
  }

  private static SECPSignature parseProposerSeal(final Bytes proposerSealRaw) {
    return proposerSealRaw.isZero()
        ? null
        : SignatureAlgorithmFactory.getInstance().decodeSignature(proposerSealRaw);
  }

  private static List<Address> extractValidators(final Bytes validatorsRaw) {
    final List<Address> result = Lists.newArrayList();
    final int countValidators = validatorsRaw.size() / Address.SIZE;
    for (int i = 0; i < countValidators; i++) {
      final int startIndex = i * Address.SIZE;
      result.add(Address.wrap(validatorsRaw.slice(startIndex, Address.SIZE)));
    }
    return result;
  }

  /**
   * Encode to bytes.
   *
   * @return the bytes
   */
  public Bytes encode() {
    return encode(vanityData, validators, proposerSeal1, proposerSeal2);
  }

  /**
   * Encode unsealed to bytes.
   *
   * @param vanityData the vanity data
   * @param validators the validators
   * @return the bytes
   */
  public static Bytes encodeUnsealed(final Bytes vanityData, final List<Address> validators) {
    return encode(vanityData, validators, Optional.empty(), Optional.empty());
  }

  private static Bytes encode(
      final Bytes vanityData,
      final List<Address> validators,
      final Optional<SECPSignature> proposerSeal1,
      final Optional<SECPSignature> proposerSeal2) {
    final Bytes validatorData = Bytes.concatenate(validators.toArray(new Bytes[0]));

    Bytes seal1Bytes =
        proposerSeal1
            .map(SECPSignature::encodedBytes)
            .orElse(Bytes.wrap(new byte[SECPSignature.BYTES_REQUIRED]));
    Bytes seal2Bytes =
        proposerSeal2
            .map(SECPSignature::encodedBytes)
            .orElse(Bytes.wrap(new byte[SECPSignature.BYTES_REQUIRED]));
    return Bytes.concatenate(vanityData, validatorData, seal1Bytes, seal2Bytes);
  }

  /**
   * Gets vanity data.
   *
   * @return the vanity data
   */
  public Bytes getVanityData() {
    return vanityData;
  }

  /**
   * Gets proposer seal.
   *
   * @return the proposer seal
   */
  public Optional<SECPSignature> getProposerSeal1() {
    return proposerSeal1;
  }

  /**
   * Get the second proposer’s raw ECDSA signature.
   *
   * @return an {@link Optional} containing the second {@link SECPSignature}, or empty if none
   */
  public Optional<SECPSignature> getProposerSeal2() {
    return proposerSeal2;
  }

  /**
   * Gets validators.
   *
   * @return the validators
   */
  public List<Address> getValidators() {
    return validators;
  }

  /**
   * Create genesis extra data string.
   *
   * @param validators the validators
   * @return the string
   */
  public static String createGenesisExtraDataString(final List<Address> validators) {
    return CliqueExtraData.createWithoutProposerSeal(Bytes.wrap(new byte[32]), validators)
        .toString();
  }
}
