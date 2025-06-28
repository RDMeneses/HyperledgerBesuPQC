/*
 * Copyright contributors to Besu.
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
package org.hyperledger.besu.consensus.clique.blockcreation;

import static com.google.common.base.Preconditions.checkState;

import org.hyperledger.besu.consensus.clique.CliqueBlockHashing;
import org.hyperledger.besu.consensus.clique.CliqueBlockInterface;
import org.hyperledger.besu.consensus.clique.CliqueContext;
import org.hyperledger.besu.consensus.clique.CliqueExtraData;
import org.hyperledger.besu.consensus.common.EpochManager;
import org.hyperledger.besu.consensus.common.validator.ValidatorVote;
import org.hyperledger.besu.crypto.SECPSignature;
import org.hyperledger.besu.cryptoservices.NodeKey;
import org.hyperledger.besu.datatypes.Hash;
import org.hyperledger.besu.ethereum.ProtocolContext;
import org.hyperledger.besu.ethereum.blockcreation.AbstractBlockCreator;
import org.hyperledger.besu.ethereum.core.BlockHeader;
import org.hyperledger.besu.ethereum.core.BlockHeaderBuilder;
import org.hyperledger.besu.ethereum.core.BlockHeaderFunctions;
import org.hyperledger.besu.ethereum.core.MiningConfiguration;
import org.hyperledger.besu.ethereum.core.SealableBlockHeader;
import org.hyperledger.besu.ethereum.core.Util;
import org.hyperledger.besu.ethereum.eth.manager.EthScheduler;
import org.hyperledger.besu.ethereum.eth.transactions.TransactionPool;
import org.hyperledger.besu.ethereum.mainnet.ProtocolSchedule;
import org.hyperledger.besu.ethereum.mainnet.ScheduleBasedBlockHeaderFunctions;

import java.util.Optional;

/** The Clique block creator, producing two proposer seals per block. */
public class CliqueBlockCreator extends AbstractBlockCreator {

  private final NodeKey nodeKey1;

  //  @SuppressWarnings("UnusedVariable")
  private final NodeKey nodeKey2;

  private final EpochManager epochManager;

  /**
   * Constructs a new CliqueBlockCreator with two NodeKeys.
   *
   * @param miningConfiguration mining configuration
   * @param extraDataCalculator calculator for extra data
   * @param transactionPool pending transactions pool
   * @param protocolContext protocol context
   * @param protocolSchedule protocol schedule
   * @param nodeKey1 first node private key for signing
   * @param nodeKey2 second node private key for signing
   * @param epochManager epoch manager
   * @param ethScheduler Ethereum scheduler
   */
  public CliqueBlockCreator(
      final MiningConfiguration miningConfiguration,
      final ExtraDataCalculator extraDataCalculator,
      final TransactionPool transactionPool,
      final ProtocolContext protocolContext,
      final ProtocolSchedule protocolSchedule,
      final NodeKey nodeKey1,
      final NodeKey nodeKey2,
      final EpochManager epochManager,
      final EthScheduler ethScheduler) {
    super(
        miningConfiguration,
        __ -> Util.publicKeyToAddress(nodeKey1.getPublicKey()),
        extraDataCalculator,
        transactionPool,
        protocolContext,
        protocolSchedule,
        ethScheduler);

    this.nodeKey1 = nodeKey1;
    this.nodeKey2 = nodeKey2;
    this.epochManager = epochManager;
  }

  @Override
  protected BlockHeader createFinalBlockHeader(final SealableBlockHeader sealableBlockHeader) {
    final BlockHeaderFunctions blockHeaderFunctions =
        ScheduleBasedBlockHeaderFunctions.create(protocolSchedule);

    final BlockHeaderBuilder builder =
        BlockHeaderBuilder.create()
            .populateFrom(sealableBlockHeader)
            .mixHash(Hash.ZERO)
            .blockHeaderFunctions(blockHeaderFunctions);

    final Optional<ValidatorVote> vote = determineCliqueVote(sealableBlockHeader);
    final BlockHeaderBuilder builderIncludingProposedVotes =
        CliqueBlockInterface.createHeaderBuilderWithVoteHeaders(builder, vote);
    final CliqueExtraData sealedExtraData =
        constructSignedExtraData(builderIncludingProposedVotes.buildBlockHeader());

    return builderIncludingProposedVotes.extraData(sealedExtraData.encode()).buildBlockHeader();
  }

  private Optional<ValidatorVote> determineCliqueVote(
      final SealableBlockHeader sealableBlockHeader) {
    final BlockHeader parentHeader =
        protocolContext.getBlockchain().getBlockHeader(sealableBlockHeader.getParentHash()).get();
    if (epochManager.isEpochBlock(sealableBlockHeader.getNumber())) {
      return Optional.empty();
    }
    final CliqueContext cliqueContext = protocolContext.getConsensusContext(CliqueContext.class);
    checkState(
        cliqueContext.getValidatorProvider().getVoteProviderAtHead().isPresent(),
        "Clique requires a vote provider");
    return cliqueContext
        .getValidatorProvider()
        .getVoteProviderAtHead()
        .get()
        .getVoteAfterBlock(parentHeader, Util.publicKeyToAddress(nodeKey1.getPublicKey()));
  }

  /**
   * Produces a CliqueExtraData with two proposer seals.
   *
   * @param headerToSign the header to sign (without seals)
   * @return a new CliqueExtraData carrying two proposer seals
   */
  private CliqueExtraData constructSignedExtraData(final BlockHeader headerToSign) {
    final CliqueExtraData extraData = CliqueExtraData.decode(headerToSign);
    final Hash hashToSign =
        CliqueBlockHashing.calculateDataHashForProposerSeal(headerToSign, extraData);
    final SECPSignature proposerSeal1 = nodeKey1.sign(hashToSign);
    final SECPSignature proposerSeal2 = nodeKey2.sign(hashToSign);
    return new CliqueExtraData(
        extraData.getVanityData(),
        proposerSeal1,
        proposerSeal2,
        extraData.getValidators(),
        headerToSign);
  }
}
