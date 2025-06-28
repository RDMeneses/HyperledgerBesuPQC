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
package org.hyperledger.besu.controller;

import org.hyperledger.besu.config.CliqueConfigOptions;
import org.hyperledger.besu.consensus.clique.CliqueBlockInterface;
import org.hyperledger.besu.consensus.clique.CliqueContext;
import org.hyperledger.besu.consensus.clique.CliqueForksSchedulesFactory;
import org.hyperledger.besu.consensus.clique.CliqueHelpers;
import org.hyperledger.besu.consensus.clique.CliqueMiningTracker;
import org.hyperledger.besu.consensus.clique.CliqueProtocolSchedule;
import org.hyperledger.besu.consensus.clique.blockcreation.CliqueBlockScheduler;
import org.hyperledger.besu.consensus.clique.blockcreation.CliqueMinerExecutor;
import org.hyperledger.besu.consensus.clique.blockcreation.CliqueMiningCoordinator;
import org.hyperledger.besu.consensus.clique.jsonrpc.CliqueJsonRpcMethods;
import org.hyperledger.besu.consensus.common.BlockInterface;
import org.hyperledger.besu.consensus.common.EpochManager;
import org.hyperledger.besu.consensus.common.ForksSchedule;
import org.hyperledger.besu.consensus.common.validator.blockbased.BlockValidatorProvider;
import org.hyperledger.besu.cryptoservices.NodeKey;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.ethereum.ProtocolContext;
import org.hyperledger.besu.ethereum.api.jsonrpc.methods.JsonRpcMethods;
import org.hyperledger.besu.ethereum.blockcreation.MiningCoordinator;
import org.hyperledger.besu.ethereum.chain.Blockchain;
import org.hyperledger.besu.ethereum.core.BlockHeader;
import org.hyperledger.besu.ethereum.core.MiningConfiguration;
import org.hyperledger.besu.ethereum.core.Util;
import org.hyperledger.besu.ethereum.eth.manager.EthProtocolManager;
import org.hyperledger.besu.ethereum.eth.sync.state.SyncState;
import org.hyperledger.besu.ethereum.eth.transactions.TransactionPool;
import org.hyperledger.besu.ethereum.mainnet.ProtocolSchedule;
import org.hyperledger.besu.ethereum.worldstate.WorldStateArchive;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** The Clique consensus controller builder. */
public class CliqueBesuControllerBuilder extends BesuControllerBuilder {

  private static final Logger LOG = LoggerFactory.getLogger(CliqueBesuControllerBuilder.class);

  private Address localAddress;
  private EpochManager epochManager;
  private final BlockInterface blockInterface = new CliqueBlockInterface();
  private ForksSchedule<CliqueConfigOptions> forksSchedule;

  // two node keys for dual-signature support
  private NodeKey nodeKey1;
  private NodeKey nodeKey2;

  /** Default constructor. */
  public CliqueBesuControllerBuilder() {
    LOG.debug("Instantiated CliqueBesuControllerBuilder");
  }

  @Override
  protected void prepForBuild() {
    LOG.info("Preparing CliqueBesuControllerBuilder for build");
    // initialize both keys (fallback to single key if second not provided)
    this.nodeKey1 = this.nodeKey;
    this.nodeKey2 = this.nodeKey;
    LOG.debug("NodeKey1 and NodeKey2 initialized: {}", nodeKey1.getPublicKey());

    localAddress = Util.publicKeyToAddress(nodeKey1.getPublicKey());
    LOG.info("Local address set to {}", localAddress);
    final CliqueConfigOptions cliqueConfig = genesisConfigOptions.getCliqueConfigOptions();
    final long blocksPerEpoch = cliqueConfig.getEpochLength();
    LOG.debug("Clique epoch length: {} blocks", blocksPerEpoch);

    epochManager = new EpochManager((int) blocksPerEpoch);
    forksSchedule = CliqueForksSchedulesFactory.create(genesisConfigOptions);
    LOG.debug("Forks schedule created: {}", forksSchedule);
  }

  @Override
  protected JsonRpcMethods createAdditionalJsonRpcMethodFactory(
      final ProtocolContext protocolContext,
      final ProtocolSchedule protocolSchedule,
      final MiningConfiguration miningConfiguration) {
    LOG.info("Creating Clique JSON-RPC methods");
    return new CliqueJsonRpcMethods(protocolContext, protocolSchedule, miningConfiguration);
  }

  @Override
  protected MiningCoordinator createMiningCoordinator(
      final ProtocolSchedule protocolSchedule,
      final ProtocolContext protocolContext,
      final TransactionPool transactionPool,
      final MiningConfiguration miningConfiguration,
      final SyncState syncState,
      final EthProtocolManager ethProtocolManager) {
    LOG.info("Creating Clique MiningCoordinator");
    LOG.debug("Using protocolSchedule: {}", protocolSchedule);

    final CliqueMinerExecutor miningExecutor =
        new CliqueMinerExecutor(
            protocolContext,
            protocolSchedule,
            transactionPool,
            nodeKey1,
            nodeKey2,
            miningConfiguration,
            new CliqueBlockScheduler(
                clock,
                protocolContext.getConsensusContext(CliqueContext.class).getValidatorProvider(),
                localAddress,
                forksSchedule),
            epochManager,
            forksSchedule,
            ethProtocolManager.ethContext().getScheduler());

    LOG.debug("CliqueMinerExecutor created: {}", miningExecutor);

    final CliqueMiningCoordinator miningCoordinator =
        new CliqueMiningCoordinator(
            protocolContext.getBlockchain(),
            miningExecutor,
            syncState,
            new CliqueMiningTracker(localAddress, protocolContext));

    LOG.info("Mining coordinator initialized");

    protocolContext
        .getBlockchain()
        .observeBlockAdded(
            o -> {
              long nextBlock = o.getBlock().getHeader().getNumber() + 1;
              long nextPeriod = forksSchedule.getFork(nextBlock).getValue().getBlockPeriodSeconds();
              miningConfiguration.setBlockPeriodSeconds((int) nextPeriod);
              LOG.debug("Block {} added, next period set to {}s", nextBlock, nextPeriod);
            });

    miningCoordinator.addMinedBlockObserver(ethProtocolManager);
    LOG.debug("EthProtocolManager observer added");

    miningCoordinator.enable();
    LOG.info("Clique mining enabled");
    return miningCoordinator;
  }

  @Override
  protected ProtocolSchedule createProtocolSchedule() {
    LOG.info("Creating Clique protocol schedule");
    ProtocolSchedule schedule =
        CliqueProtocolSchedule.create(
            genesisConfigOptions,
            forksSchedule,
            nodeKey1,
            privacyParameters,
            isRevertReasonEnabled,
            evmConfiguration,
            miningConfiguration,
            badBlockManager,
            isParallelTxProcessingEnabled,
            metricsSystem);
    LOG.debug("Protocol schedule created: {}", schedule);
    return schedule;
  }

  @Override
  protected void validateContext(final ProtocolContext context) {
    LOG.info("Validating consensus context");
    final BlockHeader genesisBlockHeader = context.getBlockchain().getGenesisBlock().getHeader();

    if (blockInterface.validatorsInBlock(genesisBlockHeader).isEmpty()) {
      LOG.warn("Genesis block contains no signers - chain will not progress.");
    } else {
      LOG.debug(
          "Validators in genesis block: {}", blockInterface.validatorsInBlock(genesisBlockHeader));
    }
  }

  @Override
  protected PluginServiceFactory createAdditionalPluginServices(
      final Blockchain blockchain, final ProtocolContext protocolContext) {
    LOG.info("Creating additional plugin services");
    return new CliqueQueryPluginServiceFactory(blockchain, nodeKey);
  }

  @Override
  protected CliqueContext createConsensusContext(
      final Blockchain blockchain,
      final WorldStateArchive worldStateArchive,
      final ProtocolSchedule protocolSchedule) {
    LOG.info("Setting up Clique consensus context");
    final CliqueContext cliqueContext =
        new CliqueContext(
            BlockValidatorProvider.nonForkingValidatorProvider(
                blockchain, epochManager, blockInterface),
            epochManager,
            blockInterface);
    CliqueHelpers.setCliqueContext(cliqueContext);
    CliqueHelpers.installCliqueBlockChoiceRule(blockchain, cliqueContext);
    LOG.debug("Clique consensus context initialized");
    return cliqueContext;
  }

  @Override
  public MiningConfiguration getMiningParameterOverrides(final MiningConfiguration fromCli) {
    LOG.info("Overriding mining parameters: enabling mining");
    return fromCli.setMiningEnabled(true);
  }
}
