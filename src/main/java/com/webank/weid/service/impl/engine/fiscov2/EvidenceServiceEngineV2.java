/*
 *       Copyright© (2018-2020) WeBank Co., Ltd.
 *
 *       This file is part of weid-java-sdk.
 *
 *       weid-java-sdk is free software: you can redistribute it and/or modify
 *       it under the terms of the GNU Lesser General Public License as published by
 *       the Free Software Foundation, either version 3 of the License, or
 *       (at your option) any later version.
 *
 *       weid-java-sdk is distributed in the hope that it will be useful,
 *       but WITHOUT ANY WARRANTY; without even the implied warranty of
 *       MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *       GNU Lesser General Public License for more details.
 *
 *       You should have received a copy of the GNU Lesser General Public License
 *       along with weid-java-sdk.  If not, see <https://www.gnu.org/licenses/>.
 */

package com.webank.weid.service.impl.engine.fiscov2;

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.fisco.bcos.web3j.abi.datatypes.generated.Bytes32;
import org.fisco.bcos.web3j.abi.datatypes.generated.Uint256;
import org.fisco.bcos.web3j.protocol.Web3j;
import org.fisco.bcos.web3j.protocol.core.DefaultBlockParameterNumber;
import org.fisco.bcos.web3j.protocol.core.methods.response.BcosBlock;
import org.fisco.bcos.web3j.protocol.core.methods.response.BcosTransactionReceipt;
import org.fisco.bcos.web3j.protocol.core.methods.response.Log;
import org.fisco.bcos.web3j.protocol.core.methods.response.Transaction;
import org.fisco.bcos.web3j.protocol.core.methods.response.TransactionReceipt;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.webank.weid.constant.ErrorCode;
import com.webank.weid.constant.ResolveEventLogStatus;
import com.webank.weid.constant.WeIdConstant;
import com.webank.weid.contract.v2.EvidenceContract;
import com.webank.weid.contract.v2.EvidenceContract.EvidenceAttributeChangedEventResponse;
import com.webank.weid.protocol.base.EvidenceInfo;
import com.webank.weid.protocol.base.EvidenceSignInfo;
import com.webank.weid.protocol.response.ResolveEventLogResult;
import com.webank.weid.protocol.response.ResponseData;
import com.webank.weid.protocol.response.TransactionInfo;
import com.webank.weid.service.impl.engine.BaseEngine;
import com.webank.weid.service.impl.engine.EvidenceServiceEngine;
import com.webank.weid.util.DataToolUtils;
import com.webank.weid.util.WeIdUtils;

/**
 * EvidenceServiceEngine calls evidence contract which runs on FISCO BCOS 2.0.
 *
 * @author yanggang, chaoxinhu
 */
public class EvidenceServiceEngineV2 extends BaseEngine implements EvidenceServiceEngine {

    private static final Logger logger = LoggerFactory.getLogger(EvidenceServiceEngineV2.class);

    private static EvidenceContract evidenceContract;

    /**
     * 构造函数.
     */
    public EvidenceServiceEngineV2() {
        if (evidenceContract == null) {
            reload();
        }
    }

    /**
     * 重新加载静态合约对象.
     */
    @Override
    public void reload() {
        evidenceContract = getContractService(
            fiscoConfig.getEvidenceAddress(),
            EvidenceContract.class);
    }

    // 往 链上创建 Evidence
    @Override
    public ResponseData<String> createEvidence(
        String hashValue,
        String signature,
        String extra,
        Long timestamp,
        String privateKey
    ) {
        try {
            List<byte[]> hashByteList = new ArrayList<>();
            if (!DataToolUtils.isValidHash(hashValue)) {
                return new ResponseData<>(StringUtils.EMPTY, ErrorCode.ILLEGAL_INPUT, null);
            }
            hashByteList.add(DataToolUtils.convertHashStrIntoHashByte32Array(hashValue));
            String address = WeIdUtils
                .convertWeIdToAddress(DataToolUtils.convertPrivateKeyToDefaultWeId(privateKey));
            List<String> signerList = new ArrayList<>();
            signerList.add(address);
            List<String> sigList = new ArrayList<>();
            sigList.add(signature);
            List<String> logList = new ArrayList<>();
            logList.add(extra);
            List<BigInteger> timestampList = new ArrayList<>();
            timestampList.add(new BigInteger(String.valueOf(timestamp), 10));
            EvidenceContract evidenceContractWriter =
                reloadContract(
                    fiscoConfig.getEvidenceAddress(),
                    privateKey,
                    EvidenceContract.class
                );

            // 调用 EvidenceContract 合约 往链上存储 Evidence
            TransactionReceipt receipt =
                evidenceContractWriter.createEvidence(
                    hashByteList,   // 我们从上面的代码中可以知道,  List 中目前只有一个 元素
                    signerList,
                    sigList,
                    logList,
                    timestampList
                ).send();

            TransactionInfo info = new TransactionInfo(receipt);
            List<EvidenceAttributeChangedEventResponse> eventList =
                evidenceContract.getEvidenceAttributeChangedEvents(receipt);
            if (eventList == null || eventList.isEmpty()) {
                return new ResponseData<>(StringUtils.EMPTY,
                    ErrorCode.CREDENTIAL_EVIDENCE_BASE_ERROR, info);
            } else {
                for (EvidenceAttributeChangedEventResponse event : eventList) {
                    if (event.sigs.toArray()[0].toString().equalsIgnoreCase(signature)
                        && event.signer.toArray()[0].toString().equalsIgnoreCase(address)) {
                        return new ResponseData<>(hashValue, ErrorCode.SUCCESS, info);
                    }
                }
            }
            return new ResponseData<>(StringUtils.EMPTY,
                ErrorCode.CREDENTIAL_EVIDENCE_CONTRACT_FAILURE_ILLEAGAL_INPUT);
        } catch (Exception e) {
            logger.error("create evidence failed due to system error. ", e);
            return new ResponseData<>(StringUtils.EMPTY, ErrorCode.CREDENTIAL_EVIDENCE_BASE_ERROR);
        }
    }

    @Override
    public ResponseData<List<Boolean>> batchCreateEvidence(
        List<String> hashValues,
        List<String> signatures,
        List<String> logs,
        List<Long> timestamp,
        List<String> signers,
        String privateKey
    ) {
        List<Boolean> result = new ArrayList<>();
        for (int i = 0; i < hashValues.size(); i++) {
            result.add(false);
        }
        try {
            List<byte[]> hashByteList = new ArrayList<>();
            List<String> signerList = new ArrayList<>();
            List<BigInteger> timestampList = new ArrayList<>();
            List<String> logList = new ArrayList<>();
            List<String> sigList = new ArrayList<>();
            for (int i = 0; i < hashValues.size(); i++) {
                if (hashValues.get(i) == null) {
                    hashValues.set(i, StringUtils.EMPTY);
                }
                if (!DataToolUtils.isValidHash(hashValues.get(i))) {
                    continue;
                }
                hashByteList
                    .add(DataToolUtils.convertHashStrIntoHashByte32Array(hashValues.get(i)));
                signerList.add(WeIdUtils.convertWeIdToAddress(signers.get(i)));
                timestampList.add(new BigInteger(String.valueOf(timestamp.get(i)), 10));
                logList.add(logs.get(i));
                sigList.add(signatures.get(i));
            }
            EvidenceContract evidenceContractWriter =
                reloadContract(
                    fiscoConfig.getEvidenceAddress(),
                    privateKey,
                    EvidenceContract.class
                );
            TransactionReceipt receipt =
                evidenceContractWriter.createEvidence(
                    hashByteList,
                    signerList,
                    sigList,
                    logList,
                    timestampList
                ).sendAsync().get(WeIdConstant.TRANSACTION_RECEIPT_TIMEOUT, TimeUnit.SECONDS);

            TransactionInfo info = new TransactionInfo(receipt);
            List<EvidenceAttributeChangedEventResponse> eventList =
                evidenceContractWriter.getEvidenceAttributeChangedEvents(receipt);
            if (eventList == null || eventList.isEmpty()) {
                return new ResponseData<>(result,
                    ErrorCode.CREDENTIAL_EVIDENCE_BASE_ERROR, info);
            } else {
                List<String> returnedHashs = new ArrayList<>();
                for (EvidenceAttributeChangedEventResponse event : eventList) {
                    Object[] hashArray = event.hash.toArray();
                    for (int i = 0; i < CollectionUtils.size(event.hash); i++) {
                        returnedHashs.add(DataToolUtils.convertHashByte32ArrayIntoHashStr(
                            ((org.fisco.bcos.web3j.abi.datatypes.generated.Bytes32) (hashArray[i]))
                                .getValue()));
                    }
                }
                return new ResponseData<>(
                    DataToolUtils.strictCheckExistence(hashValues, returnedHashs),
                    ErrorCode.SUCCESS, info);
            }
        } catch (Exception e) {
            logger.error("create evidence failed due to system error. ", e);
            return new ResponseData<>(result, ErrorCode.CREDENTIAL_EVIDENCE_BASE_ERROR);
        }
    }

    @Override
    public ResponseData<List<Boolean>> batchCreateEvidenceWithCustomKey(
        List<String> hashValues,
        List<String> signatures,
        List<String> logs,
        List<Long> timestamp,
        List<String> signers,
        List<String> customKeys,
        String privateKey
    ) {
        List<Boolean> result = new ArrayList<>();
        for (int i = 0; i < hashValues.size(); i++) {
            result.add(false);
        }
        try {
            List<byte[]> hashByteList = new ArrayList<>();
            List<String> signerList = new ArrayList<>();
            List<BigInteger> timestampList = new ArrayList<>();
            List<String> customKeyList = new ArrayList<>();
            List<String> logList = new ArrayList<>();
            List<String> sigList = new ArrayList<>();
            for (int i = 0; i < hashValues.size(); i++) {
                if (hashValues.get(i) == null) {
                    hashValues.set(i, StringUtils.EMPTY);
                }
                if (!DataToolUtils.isValidHash(hashValues.get(i))) {
                    continue;
                }
                hashByteList
                    .add(DataToolUtils.convertHashStrIntoHashByte32Array(hashValues.get(i)));
                signerList.add(WeIdUtils.convertWeIdToAddress(signers.get(i)));
                timestampList.add(new BigInteger(String.valueOf(timestamp.get(i)), 10));
                customKeyList.add(customKeys.get(i));
                logList.add(logs.get(i));
                sigList.add(signatures.get(i));
            }

            // 获取 EvidenceContract 合约实例
            EvidenceContract evidenceContractWriter =
                reloadContract(
                    fiscoConfig.getEvidenceAddress(),
                    privateKey,
                    EvidenceContract.class
                );


            // 调用 EvidenceContract 合约的 createEvidenceWithExtraKey() 方法
            TransactionReceipt receipt =
                evidenceContractWriter.createEvidenceWithExtraKey(
                    hashByteList,
                    signerList,
                    sigList,
                    logList,
                    timestampList,
                    customKeyList
                ).sendAsync().get(WeIdConstant.TRANSACTION_RECEIPT_TIMEOUT, TimeUnit.SECONDS);

            TransactionInfo info = new TransactionInfo(receipt);
            List<EvidenceAttributeChangedEventResponse> eventList =
                evidenceContractWriter.getEvidenceAttributeChangedEvents(receipt);
            if (eventList == null || eventList.isEmpty()) {
                return new ResponseData<>(result,
                    ErrorCode.CREDENTIAL_EVIDENCE_BASE_ERROR, info);
            } else {
                List<String> returnedHashs = new ArrayList<>();
                for (EvidenceAttributeChangedEventResponse event : eventList) {
                    Object[] hashArray = event.hash.toArray();
                    for (int i = 0; i < CollectionUtils.size(event.hash); i++) {
                        returnedHashs.add(DataToolUtils.convertHashByte32ArrayIntoHashStr(
                            ((org.fisco.bcos.web3j.abi.datatypes.generated.Bytes32) (hashArray[i]))
                                .getValue()));
                    }
                }
                return new ResponseData<>(
                    DataToolUtils.strictCheckExistence(hashValues, returnedHashs),
                    ErrorCode.SUCCESS, info);
            }
        } catch (Exception e) {
            logger.error("create evidence failed due to system error. ", e);
            return new ResponseData<>(result, ErrorCode.CREDENTIAL_EVIDENCE_BASE_ERROR);
        }
    }

    @Override
    public ResponseData<Boolean> addLog(
        String hashValue,
        String log,
        Long timestamp,
        String privateKey
    ) {
        try {
            List<byte[]> hashByteList = new ArrayList<>();
            if (!DataToolUtils.isValidHash(hashValue)) {
                return new ResponseData<>(false, ErrorCode.ILLEGAL_INPUT, null);
            }
            hashByteList.add(DataToolUtils.convertHashStrIntoHashByte32Array(hashValue));
            List<String> sigList = new ArrayList<>();
            sigList.add(StringUtils.EMPTY);
            List<String> logList = new ArrayList<>();
            logList.add(log);
            List<BigInteger> timestampList = new ArrayList<>();
            timestampList.add(new BigInteger(String.valueOf(timestamp), 10));

            // 使用 PriKey 算出 账户地址, WeId
            String address = WeIdUtils
                .convertWeIdToAddress(DataToolUtils.convertPrivateKeyToDefaultWeId(privateKey));
            List<String> signerList = new ArrayList<>();
            signerList.add(address);
            EvidenceContract evidenceContractWriter =
                reloadContract(
                    fiscoConfig.getEvidenceAddress(),
                    privateKey,
                    EvidenceContract.class
                );
            signerList.add(address);

            // 调用 EvidenceContract  合约, createEvidence() 方法, 存入一个 新的 Evidence 信息
            TransactionReceipt receipt =
                evidenceContractWriter.createEvidence(
                    hashByteList,
                    signerList,
                    sigList,
                    logList, // 拓展信息, 可以为 null  “”
                    timestampList
                ).send();
            TransactionInfo info = new TransactionInfo(receipt);
            List<EvidenceAttributeChangedEventResponse> eventList =
                evidenceContractWriter.getEvidenceAttributeChangedEvents(receipt);
            if (eventList == null || eventList.isEmpty()) {
                return new ResponseData<>(false, ErrorCode.CREDENTIAL_EVIDENCE_BASE_ERROR, info);
            } else {
                for (EvidenceAttributeChangedEventResponse event : eventList) {
                    // 对比下, 签名者 是否正确
                    if (event.signer.toArray()[0].toString().equalsIgnoreCase(address)) {
                        return new ResponseData<>(true, ErrorCode.SUCCESS, info);
                    }
                }
            }
            return new ResponseData<>(false,
                ErrorCode.CREDENTIAL_EVIDENCE_CONTRACT_FAILURE_ILLEAGAL_INPUT);
        } catch (Exception e) {
            logger.error("add log failed due to system error. ", e);
            return new ResponseData<>(false, ErrorCode.CREDENTIAL_EVIDENCE_BASE_ERROR);
        }
    }

    @Override
    public ResponseData<String> getHashByCustomKey(String customKey) {
        try {
            String hash = DataToolUtils.convertHashByte32ArrayIntoHashStr(

                    // 调用 EvidenceContract 合约的 getHashByExtraKey() 方法, 使用 用户之前对EvidenceHash 的描述信息, 返回对应的Evidence Hash
                evidenceContract.getHashByExtraKey(customKey).send());
            if (!StringUtils.isEmpty(hash)) {
                return new ResponseData<>(hash, ErrorCode.SUCCESS);
            }
        } catch (Exception e) {
            logger.error("get hash failed.", e);
        }
        return new ResponseData<>(StringUtils.EMPTY, ErrorCode.CREDENTIAL_EVIDENCE_NOT_EXIST);
    }

    /**
     *
     * todo 获取 Evidence 的完整数据
     * Get an evidence full info.
     *
     * @param hash evidence hash
     * @return evidence info
     */
    @Override
    public ResponseData<EvidenceInfo> getInfo(String hash) {

        // new了一个空的 Evidence信息
        EvidenceInfo evidenceInfo = new EvidenceInfo();
        evidenceInfo.setCredentialHash(hash);
        int latestBlockNumber = 0;
        byte[] hashByte = DataToolUtils.convertHashStrIntoHashByte32Array(hash);
        try {

            // 根据 Evidence Hash 先获取 最后一次存放 Evidence 信息的 blockNumber
            latestBlockNumber = evidenceContract.getLatestRelatedBlock(hashByte).send().intValue();
            if (latestBlockNumber == 0) {
                return new ResponseData<>(null, ErrorCode.CREDENTIAL_EVIDENCE_NOT_EXIST);
            }

            // todo 逐个 处理 Evidence 的信息, 并回填到 evidenceInfo
            resolveTransaction(hash, latestBlockNumber, evidenceInfo);
            // Reverse the order of the list
            for (String signer : evidenceInfo.getSigners()) {
                List<String> extraList = evidenceInfo.getSignInfo().get(signer).getLogs();
                if (extraList != null && !extraList.isEmpty()) {
                    Collections.reverse(evidenceInfo.getSignInfo().get(signer).getLogs());
                }
            }
            return new ResponseData<>(evidenceInfo, ErrorCode.SUCCESS);
        } catch (Exception e) {
            logger.error("get evidence failed.", e);
            return new ResponseData<>(null, ErrorCode.CREDENTIAL_EVIDENCE_BASE_ERROR);
        }
    }

    private static void resolveTransaction(
        String hash,
        int startBlockNumber,
        EvidenceInfo evidenceInfo) {

        // 遍历 所有涉及的 block
        int previousBlock = startBlockNumber;
        while (previousBlock != 0) {
            int currentBlockNumber = previousBlock;
            BcosBlock latestBlock = null;
            try {
                latestBlock = ((Web3j) getWeb3j()).getBlockByNumber(
                    new DefaultBlockParameterNumber(currentBlockNumber), true).send();
            } catch (IOException e) {
                logger.error(
                    "Get block by number:{} failed. Exception message:{}", currentBlockNumber, e);
            }
            if (latestBlock == null) {
                logger.info("Get block by number:{}. latestBlock is null", currentBlockNumber);
                return;
            }

            // 获取当前 block 的所有 tx
            List<Transaction> transList = latestBlock
                .getBlock()
                .getTransactions()
                .stream()
                .map(transactionResult -> (Transaction) transactionResult.get())
                .collect(Collectors.toList());
            previousBlock = 0;
            try {

                // 遍历目标block 的所有 tx
                for (Transaction transaction : transList) {
                    String transHash = transaction.getHash();

                    // 获取当前 tx 的 所有receipt
                    BcosTransactionReceipt rec1 = ((Web3j) getWeb3j())
                        .getTransactionReceipt(transHash)
                        .send();
                    TransactionReceipt receipt = rec1.getTransactionReceipt().get();
                    List<Log> logs = rec1.getResult().getLogs();
                    // A same topic will be calculated only once
                    // 同一主题仅计算一次  (去重)
                    Set<String> topicSet = new HashSet<>();

                    // 遍历当前 txReceipt 的所有 logs
                    for (Log log : logs) {
                        if (topicSet.contains(log.getTopics().get(0))) {
                            continue;
                        } else {
                            topicSet.add(log.getTopics().get(0));
                        }

                        // todo  开始处理当前 log, 将信息 回写 到 evidenceInfo
                        ResolveEventLogResult returnValue =
                            resolveEventLog(hash, log, receipt, evidenceInfo);
                        if (returnValue.getResultStatus().equals(
                            ResolveEventLogStatus.STATUS_SUCCESS)) {
                            if (returnValue.getPreviousBlock() == currentBlockNumber) {
                                continue;
                            }
                            previousBlock = returnValue.getPreviousBlock();
                        }
                    }
                }
            } catch (Exception e) {
                logger.error("Get TransactionReceipt by key :{} failed.", hash, e);
            }
        }
    }

    private static ResolveEventLogResult resolveEventLog(
        String hash,
        Log log,
        TransactionReceipt receipt,
        EvidenceInfo evidenceInfo) {
        String topic = log.getTopics().get(0);
        if (!StringUtils.isBlank(topic)) {
            // 来, 处理 log 中的 evidence 信息, 回写到 evidenceInfo 中
            return resolveAttributeEvent(hash, receipt, evidenceInfo);
        }
        ResolveEventLogResult response = new ResolveEventLogResult();
        response.setResolveEventLogStatus(ResolveEventLogStatus.STATUS_EVENT_NULL);
        return response;
    }

    private static ResolveEventLogResult resolveAttributeEvent(
        String hash,
        TransactionReceipt receipt,
        EvidenceInfo evidenceInfo) {

        // 根据当前 receipt 获取所有的 events
        List<EvidenceAttributeChangedEventResponse> eventList =
            evidenceContract.getEvidenceAttributeChangedEvents(receipt);
        ResolveEventLogResult response = new ResolveEventLogResult();
        if (CollectionUtils.isEmpty(eventList)) {
            response.setResolveEventLogStatus(ResolveEventLogStatus.STATUS_EVENTLOG_NULL);
            return response;
        }

        int previousBlock = 0;
        // Actual construction code
        // there should be only 1 attrib-change event so it is fine to do so
        //
        // 实际施工规范
        // 应该只有1个attrib-change事件，所以这样做很好
        //
        // 遍历所有 event
        for (EvidenceAttributeChangedEventResponse event : eventList) {
            if (CollectionUtils.isEmpty(event.signer) || CollectionUtils.isEmpty(event.hash)) {
                response.setResolveEventLogStatus(ResolveEventLogStatus.STATUS_RES_NULL);
                return response;
            }
            // the event is a full list of everything. Go thru the list and locate the hash
            //
            // 遍历 Hash 数组, signer 数组, logs数组
            for (int index = 0; index < CollectionUtils.size(event.hash); index++) {
                if (hash.equalsIgnoreCase(DataToolUtils.convertHashByte32ArrayIntoHashStr(
                    ((Bytes32) event.hash.toArray()[index]).getValue()))) {

                    // 提取出对应 index 下的单个 signer的 WeId
                    String signerWeId = WeIdUtils
                        .convertAddressToWeId(event.signer.toArray()[index].toString());
                    String currentLog = event.logs.toArray()[index].toString();
                    String currentSig = event.sigs.toArray()[index].toString();
                    if (!StringUtils.isEmpty(currentLog) && !StringUtils.isEmpty(currentSig)) {
                        // this is a sign/log event, sig will override unconditionally,
                        // but logs will try to append.
                        EvidenceSignInfo signInfo = new EvidenceSignInfo();
                        signInfo.setSignature(currentSig);
                        if (evidenceInfo.getSignInfo().containsKey(signerWeId)) {
                            signInfo.setTimestamp(
                                evidenceInfo.getSignInfo().get(signerWeId).getTimestamp());
                            List<String> oldLogs = evidenceInfo.getSignInfo().get(signerWeId)
                                .getLogs();
                            oldLogs.add(currentLog);
                            signInfo.setLogs(oldLogs);
                        } else {
                            signInfo
                                .setTimestamp(String.valueOf(
                                    ((Uint256) event.updated.toArray()[index]).getValue()
                                        .longValue()));
                            signInfo.getLogs().add(currentLog);
                        }
                        evidenceInfo.getSignInfo().put(signerWeId, signInfo);
                    } else if (!StringUtils.isEmpty(currentLog)) {
                        // this is a pure log event, just keep appending
                        EvidenceSignInfo tempInfo = new EvidenceSignInfo();
                        if (evidenceInfo.getSignInfo().containsKey(signerWeId)) {
                            // already existing evidenceInfo, hence just append a log entry.
                            // sig will override, timestamp will use existing one (always newer)
                            tempInfo.setSignature(
                                evidenceInfo.getSignInfo().get(signerWeId).getSignature());

                            tempInfo.setTimestamp(
                                evidenceInfo.getSignInfo().get(signerWeId).getTimestamp());

                            List<String> oldLogs = evidenceInfo.getSignInfo().get(signerWeId)
                                .getLogs();
                            oldLogs.add(currentLog);
                            tempInfo.setLogs(oldLogs);

                        } else {
                            // haven't constructed anything yet, so create a new one now
                            tempInfo.setSignature(StringUtils.EMPTY);
                            tempInfo
                                .setTimestamp(String.valueOf(
                                    ((Uint256) event.updated.toArray()[index]).getValue()
                                        .longValue()));
                            tempInfo.getLogs().add(currentLog);
                        }

                        // 将 对应的 Signature 信息 和对应的 signer 的WeId 存入 Evidence 的 signInfo Map中
                        // todo 由此可见这中间可以是多个 signer => signature
                        //
                        // 这里存的是 空签名
                        evidenceInfo.getSignInfo().put(signerWeId, tempInfo);
                    } else if (!StringUtils.isEmpty(currentSig)) {
                        // this is a pure sig event, just override
                        EvidenceSignInfo signInfo = new EvidenceSignInfo();
                        signInfo.setSignature(currentSig);
                        if (evidenceInfo.getSignInfo().containsKey(signerWeId)) {
                            signInfo.setTimestamp(
                                evidenceInfo.getSignInfo().get(signerWeId).getTimestamp());
                            signInfo.setLogs(evidenceInfo.getSignInfo().get(signerWeId).getLogs());
                        } else {
                            signInfo
                                .setTimestamp(String.valueOf(
                                    ((Uint256) event.updated.toArray()[index]).getValue()
                                        .longValue()));
                        }
                        // 将 对应的 Signature 信息 和对应的 signer 的WeId 存入 Evidence 的 signInfo Map中
                        // todo 由此可见这中间可以是多个 signer => signature
                        //
                        // 这里存的是 真实的签名
                        evidenceInfo.getSignInfo().put(signerWeId, signInfo);
                    } else {
                        // An empty event
                        continue;
                    }

                    // 取出 当前 event 中存储的 上一个blockNumber引用
                    previousBlock = ((Uint256) event.previousBlock.toArray()[index]).getValue()
                        .intValue();
                }
            }
        }
        response.setPreviousBlock(previousBlock);
        response.setResolveEventLogStatus(ResolveEventLogStatus.STATUS_SUCCESS);
        return response;
    }

    /* (non-Javadoc)
     * @see com.webank.weid.service.impl.engine.EvidenceServiceEngine#createEvidence(
     * java.lang.String, java.lang.String, java.lang.String, java.lang.Long, java.lang.String,
     * java.lang.String)
     */
    @Override
    public ResponseData<String> createEvidenceWithCustomKey(
        String hashValue,
        String signature,
        String extra,
        Long timestamp,
        String extraKey,
        String privateKey) {
        try {
            List<byte[]> hashByteList = new ArrayList<>();
            if (!DataToolUtils.isValidHash(hashValue)) {
                return new ResponseData<>(StringUtils.EMPTY, ErrorCode.ILLEGAL_INPUT, null);
            }
            hashByteList.add(DataToolUtils.convertHashStrIntoHashByte32Array(hashValue));
            String address = WeIdUtils
                .convertWeIdToAddress(DataToolUtils.convertPrivateKeyToDefaultWeId(privateKey));
            List<String> signerList = new ArrayList<>();
            signerList.add(address);
            List<String> sigList = new ArrayList<>();
            sigList.add(signature);
            List<String> logList = new ArrayList<>();
            logList.add(extra);
            List<BigInteger> timestampList = new ArrayList<>();
            timestampList.add(new BigInteger(String.valueOf(timestamp), 10));
            List<String> extraKeyList = new ArrayList<>();
            extraKeyList.add(extraKey);
            EvidenceContract evidenceContractWriter =
                reloadContract(
                    fiscoConfig.getEvidenceAddress(),
                    privateKey,
                    EvidenceContract.class
                );
            TransactionReceipt receipt =
                evidenceContractWriter.createEvidenceWithExtraKey(
                    hashByteList,
                    signerList,
                    sigList,
                    logList,
                    timestampList,
                    extraKeyList
                ).send();

            TransactionInfo info = new TransactionInfo(receipt);
            List<EvidenceAttributeChangedEventResponse> eventList =
                evidenceContractWriter.getEvidenceAttributeChangedEvents(receipt);
            if (eventList == null || eventList.isEmpty()) {
                return new ResponseData<>(StringUtils.EMPTY,
                    ErrorCode.CREDENTIAL_EVIDENCE_BASE_ERROR, info);
            } else {
                for (EvidenceAttributeChangedEventResponse event : eventList) {
                    if (event.sigs.toArray()[0].toString().equalsIgnoreCase(signature)
                        && event.signer.toArray()[0].toString().equalsIgnoreCase(address)) {
                        return new ResponseData<>(hashValue, ErrorCode.SUCCESS, info);
                    }
                }
            }
            return new ResponseData<>(StringUtils.EMPTY,
                ErrorCode.CREDENTIAL_EVIDENCE_CONTRACT_FAILURE_ILLEAGAL_INPUT);
        } catch (Exception e) {
            logger.error("create evidence failed due to system error. ", e);
            return new ResponseData<>(StringUtils.EMPTY, ErrorCode.CREDENTIAL_EVIDENCE_BASE_ERROR);
        }
    }

    /* (non-Javadoc)
     * @see com.webank.weid.service.impl.engine.EvidenceServiceEngine#getInfoByCustomKey(
     * java.lang.String)
     */
    @Override
    public ResponseData<EvidenceInfo> getInfoByCustomKey(String extraKey) {

        if (StringUtils.isBlank(extraKey) || !DataToolUtils.isUtf8String(extraKey)) {
            logger.error("[getInfoByCustomKey] extraKey illegal. ");
            return new ResponseData<EvidenceInfo>(null, ErrorCode.ILLEGAL_INPUT);
        }
        try {
            String hash = DataToolUtils.convertHashByte32ArrayIntoHashStr(
                evidenceContract.getHashByExtraKey(extraKey).send());
            if (StringUtils.isBlank(hash)) {
                logger.error("[getInfoByCustomKey] extraKey dose not match any hash. ");
                return new ResponseData<EvidenceInfo>(null,
                    ErrorCode.CREDENTIAL_EVIDENCE_NOT_EXIST);
            }
            return this.getInfo(hash);
        } catch (Exception e) {
            logger.error("[getInfoByCustomKey] get evidence info failed. ", e);
            return new ResponseData<EvidenceInfo>(null, ErrorCode.CREDENTIAL_EVIDENCE_BASE_ERROR);
        }
    }
}
