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
package org.hyperledger.besu.consensus.clique.blockcreation;

import org.hyperledger.besu.config.CliqueConfigOptions;
import org.hyperledger.besu.consensus.clique.CliqueContext;
import org.hyperledger.besu.consensus.clique.CliqueExtraData;
import org.hyperledger.besu.consensus.common.ConsensusHelpers;
import org.hyperledger.besu.consensus.common.EpochManager;
import org.hyperledger.besu.consensus.common.ForksSchedule;
import org.hyperledger.besu.cryptoservices.NodeKey;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.ethereum.ProtocolContext;
import org.hyperledger.besu.ethereum.blockcreation.AbstractBlockScheduler;
import org.hyperledger.besu.ethereum.blockcreation.AbstractMinerExecutor;
import org.hyperledger.besu.ethereum.chain.MinedBlockObserver;
import org.hyperledger.besu.ethereum.chain.PoWObserver;
import org.hyperledger.besu.ethereum.core.BlockHeader;
import org.hyperledger.besu.ethereum.core.MiningConfiguration;
import org.hyperledger.besu.ethereum.core.Util;
import org.hyperledger.besu.ethereum.eth.manager.EthScheduler;
import org.hyperledger.besu.ethereum.eth.transactions.TransactionPool;
import org.hyperledger.besu.ethereum.mainnet.ProtocolSchedule;
import org.hyperledger.besu.util.Subscribers;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.Lists;
import org.apache.tuweni.bytes.Bytes;

/** The Clique miner executor. */
public class CliqueMinerExecutor extends AbstractMinerExecutor<CliqueBlockMiner> {

  private final Address localAddress;
  private final NodeKey nodeKey1;
  private final NodeKey nodeKey2;
  private final EpochManager epochManager;
  private final ForksSchedule<CliqueConfigOptions> forksSchedule;

  /**
   * Instantiates a new Clique miner executor.
   *
   * @param protocolContext the protocol context
   * @param protocolSchedule the protocol schedule
   * @param transactionPool the pending transactions
   * @param nodeKey1 the first node key
   * @param nodeKey2 the second node key
   * @param miningParams the mining params
   * @param blockScheduler the block scheduler
   * @param epochManager the epoch manager
   * @param forksSchedule the clique transitions
   * @param ethScheduler the scheduler for asynchronous block creation tasks
   */
  public CliqueMinerExecutor(
      final ProtocolContext protocolContext,
      final ProtocolSchedule protocolSchedule,
      final TransactionPool transactionPool,
      final NodeKey nodeKey1,
      final NodeKey nodeKey2,
      final MiningConfiguration miningParams,
      final AbstractBlockScheduler blockScheduler,
      final EpochManager epochManager,
      final ForksSchedule<CliqueConfigOptions> forksSchedule,
      final EthScheduler ethScheduler) {
    super(
        protocolContext,
        protocolSchedule,
        transactionPool,
        miningParams,
        blockScheduler,
        ethScheduler);
    this.nodeKey1 = nodeKey1;
    this.nodeKey2 = nodeKey2;
    this.localAddress = Util.publicKeyToAddress(nodeKey1.getPublicKey());
    this.epochManager = epochManager;
    this.forksSchedule = forksSchedule;
    miningParams.setCoinbase(localAddress);
  }

  @Override
  public CliqueBlockMiner createMiner(
      final Subscribers<MinedBlockObserver> observers,
      final Subscribers<PoWObserver> ethHashObservers,
      final BlockHeader parentHeader) {
    final Function<BlockHeader, CliqueBlockCreator> blockCreator =
        (header) ->
            new CliqueBlockCreator(
                miningConfiguration,
                this::calculateExtraData,
                transactionPool,
                protocolContext,
                protocolSchedule,
                nodeKey1,
                nodeKey2,
                epochManager,
                ethScheduler);

    return new CliqueBlockMiner(
        blockCreator,
        protocolSchedule,
        protocolContext,
        observers,
        blockScheduler,
        parentHeader,
        localAddress,
        forksSchedule);
  }

  @Override
  public Optional<Address> getCoinbase() {
    return miningConfiguration.getCoinbase();
  }

  /**
   * Calculate extra data bytes.
   *
   * @param parentHeader the parent header
   * @return the bytes
   */
  @VisibleForTesting
  Bytes calculateExtraData(final BlockHeader parentHeader) {
    final List<Address> validators = Lists.newArrayList();

    final Bytes vanityDataToInsert =
        ConsensusHelpers.zeroLeftPad(
            miningConfiguration.getExtraData(), CliqueExtraData.EXTRA_VANITY_LENGTH);
    // Building ON TOP of canonical head, if the next block is epoch, include validators.
    if (epochManager.isEpochBlock(parentHeader.getNumber() + 1)) {

      final Collection<Address> storedValidators =
          protocolContext
              .getConsensusContext(CliqueContext.class)
              .getValidatorProvider()
              .getValidatorsAfterBlock(parentHeader);
      validators.addAll(storedValidators);
    }

    return CliqueExtraData.encodeUnsealed(vanityDataToInsert, validators);
  }
}
