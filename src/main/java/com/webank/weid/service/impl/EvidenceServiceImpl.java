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

package com.webank.weid.service.impl;

import java.io.File;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

import com.google.common.base.Charsets;
import com.google.common.io.Files;
import org.apache.commons.lang3.StringUtils;
import org.bcos.web3j.crypto.Sign;
import org.bcos.web3j.crypto.Sign.SignatureData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.webank.weid.constant.ErrorCode;
import com.webank.weid.constant.ParamKeyConstant;
import com.webank.weid.constant.WeIdConstant;
import com.webank.weid.protocol.base.EvidenceInfo;
import com.webank.weid.protocol.base.EvidenceSignInfo;
import com.webank.weid.protocol.base.HashString;
import com.webank.weid.protocol.base.WeIdDocument;
import com.webank.weid.protocol.base.WeIdPrivateKey;
import com.webank.weid.protocol.inf.Hashable;
import com.webank.weid.protocol.response.ResponseData;
import com.webank.weid.rpc.EvidenceService;
import com.webank.weid.rpc.WeIdService;
import com.webank.weid.service.impl.inner.PropertiesService;
import com.webank.weid.util.BatchTransactionUtils;
import com.webank.weid.util.DataToolUtils;
import com.webank.weid.util.DateUtils;
import com.webank.weid.util.WeIdUtils;

/**
 * TODO 凭证存证上链的相关接口。
 *
 * TODO 本接口提供凭证的Hash存证的生成 上链、链上查询 及 校验等操作。
 * Service implementations for operations on Evidence.
 *
 * @author chaoxinhu 2019.1
 */
public class EvidenceServiceImpl extends AbstractService implements EvidenceService {

    private static final Logger logger = LoggerFactory.getLogger(EvidenceServiceImpl.class);

    private WeIdService weIdService = new WeIdServiceImpl();

    @Override
    public ResponseData<Boolean> createRawEvidenceWithCustomKey(
        String hashValue,
        String signature,
        String log,
        Long timestamp,
        String extraKey,
        String privateKey
    ) {
        ResponseData<String> hashResp = evidenceServiceEngine.createEvidenceWithCustomKey(
            hashValue,
            signature,
            log,
            timestamp,
            extraKey,
            privateKey
        );
        if (hashResp.getResult().equalsIgnoreCase(hashValue)) {
            return new ResponseData<>(true, ErrorCode.SUCCESS);
        } else {
            return new ResponseData<>(false, hashResp.getErrorCode(), hashResp.getErrorMessage());
        }
    }

    /**
     * todo 将传入Object计算Hash值生成存证上链，返回存证hash值。
     *      传入的私钥将会成为链上存证的签名方。
     *      【此签名方和凭证的Issuer可以不是同一方】。
     *      此接口返回的Hash值和generateHash()接口返回值一致。
     *      同样的传入Object可以由不同的私钥注册存证，它们的链上存证值将会共存。
     *
     * todo 在链上创建一个 新的 Evidence
     * Create a new evidence to the blockchain and get the evidence address.
     *
     * @param object the given Java object
     * @param weIdPrivateKey the caller WeID Authentication
     * @return Evidence address
     */
    @Override
    public ResponseData<String> createEvidence (Hashable object, WeIdPrivateKey weIdPrivateKey) {

        // todo Hashable 分别被 Credential 和 CredentialPojo 和 CredentialWrapper 和 HashString  四个实现
        // 先获取 obj 的Hash
        ResponseData<String> hashResp = getHashValue(object);
        if (StringUtils.isEmpty(hashResp.getResult())) {
            return new ResponseData<>(StringUtils.EMPTY, hashResp.getErrorCode(),
                hashResp.getErrorMessage());
        }
        if (!WeIdUtils.isPrivateKeyValid(weIdPrivateKey)) {
            return new ResponseData<>(StringUtils.EMPTY,
                ErrorCode.CREDENTIAL_PRIVATE_KEY_NOT_EXISTS);
        }

        // 使用 私钥对 Hash 进行签名
        return hashToNewEvidence(hashResp.getResult(), weIdPrivateKey.getPrivateKey(),
            StringUtils.EMPTY);
    }


    /**
     * todo 为一个已经在链上存在的存证添加额外信息记录存入其log中。
     *      有两个接口，一个是以hash值为索引，一个可以接受用户自定义索引。
     *
     *  todo 为任何现有 Evidence 设置任意额外的属性
     *
     * @param hashValue hash value,  Evidence Hash的值
     * @param log log entry - can be null or empty  额外信息, 可以为 null ""
     * @param weIdPrivateKey the signer WeID's private key
     * @return
     */
    @Override
    public ResponseData<Boolean> addLogByHash(String hashValue, String log,
        WeIdPrivateKey weIdPrivateKey) {
        if (!DataToolUtils.isValidHash(hashValue) || StringUtils.isEmpty(log)
            || !DataToolUtils.isUtf8String(log)) {
            logger.error("Evidence argument illegal input: hash or log.");
            return new ResponseData<>(false, ErrorCode.ILLEGAL_INPUT);
        }
        if (!isChainStringLengthValid(log)) {
            return new ResponseData<>(false, ErrorCode.ON_CHAIN_STRING_TOO_LONG);
        }
        if (!WeIdUtils.isPrivateKeyValid(weIdPrivateKey)) {
            return new ResponseData<>(false, ErrorCode.CREDENTIAL_PRIVATE_KEY_NOT_EXISTS);
        }
        Long timestamp = DateUtils.getNoMillisecondTimeStamp();

        // go 为任何现有 Evidence 设置任意额外的属性
        return evidenceServiceEngine.addLog(
            hashValue,
            log,
            timestamp,
            weIdPrivateKey.getPrivateKey()
        );
    }


    // todo 为一个已经在链上存在的存证添加额外信息记录存入其log中。
    //      有两个接口，一个是以hash值为索引，一个可以接受用户自定义索引。
    //
    // todo 根据 客户自定义的 ExtraKey {关键字}  log 等
    @Override
    public ResponseData<Boolean> addLogByCustomKey(String customKey, String log,
        WeIdPrivateKey weIdPrivateKey) {
        if (StringUtils.isEmpty(customKey) || !DataToolUtils.isUtf8String(customKey)) {
            logger.error("Evidence argument illegal input. ");
            return new ResponseData<>(false, ErrorCode.ILLEGAL_INPUT);
        }
        if (!isChainStringLengthValid(log)) {
            return new ResponseData<>(false, ErrorCode.ON_CHAIN_STRING_TOO_LONG);
        }
        // 调用 EvidenceContract 合约的 getHashByExtraKey() 方法, 使用 用户之前对EvidenceHash 的描述信息, 返回对应的Evidence Hash
        ResponseData<String> hashResp = evidenceServiceEngine.getHashByCustomKey(customKey);
        if (StringUtils.isEmpty(hashResp.getResult())) {
            return new ResponseData<>(false, hashResp.getErrorCode(),
                hashResp.getErrorMessage());
        }
        return this.addLogByHash(hashResp.getResult(), log, weIdPrivateKey);
    }

    // todo 将传入的任意Object计算Hash值，不需网络。
    //      可以接受**任意Hashable对象**（如凭证）、**File**（Java里的文件实例）、**String**（字符串）。
    //      对于不符合类型的入参，将返回类型不支持错误。返回值为HashString，可以直接传入CreateEvidence接口用于存证创建。
    /* (non-Javadoc)
     * @see com.webank.weid.rpc.generateHash
     * #generateHash(T object)
     */
    @Override
    public <T> ResponseData<HashString> generateHash(T object) {
        if (object == null) {
            return new ResponseData<>(null, ErrorCode.ILLEGAL_INPUT);
        }
        if (object instanceof Hashable) {
            ResponseData<String> hashResp = getHashValue((Hashable) object);
            if (StringUtils.isEmpty(hashResp.getResult())) {
                return new ResponseData<>(null, hashResp.getErrorCode(),
                    hashResp.getErrorMessage());
            }
            return new ResponseData<>(new HashString(hashResp.getResult()), ErrorCode.SUCCESS);
        }
        if (object instanceof File) {
            // This will convert all types of file into String stream
            String rawData = convertFileToString((File) object);
            if (StringUtils.isEmpty(rawData)) {
                logger.error("Failed to convert file into String: {}", ((File) object).getName());
                return new ResponseData<>(null, ErrorCode.ILLEGAL_INPUT);
            }
            return new ResponseData<>(new HashString(DataToolUtils.sha3(rawData)),
                ErrorCode.SUCCESS);
        }
        if (object instanceof String) {
            if (StringUtils.isEmpty((String) object)) {
                logger.error("Input String is blank, ignored..");
                return new ResponseData<>(null, ErrorCode.ILLEGAL_INPUT);
            }
            return new ResponseData<>(new HashString(DataToolUtils.sha3((String) object)),
                ErrorCode.SUCCESS);
        }
        logger.error("Unsupported input object type: {}", object.getClass().getCanonicalName());
        return new ResponseData<>(null, ErrorCode.ILLEGAL_INPUT);
    }

    private String convertFileToString(File file) {
        try {
            return Files.asByteSource(file).asCharSource(Charsets.UTF_8).read();
        } catch (Exception e) {
            logger.error("Failed to load file as String.", e);
            return StringUtils.EMPTY;
        }
    }

    /**
     * Obtain the hash value of a given object - supports Credential, Wrapper and Pojo, and also
     * plain hash value (no extra hashing required).
     *
     * @param object any object
     * @return hash value
     */
    private ResponseData<String> getHashValue(Hashable object) {
        if (object == null) {
            return new ResponseData<>(StringUtils.EMPTY, ErrorCode.ILLEGAL_INPUT);
        }
        try {

            // 计算出 obj 的Hash,
            // CredentialPojo 的话 是自带 salt 的Claim Hash
            String hashValue = object.getHash();
            if (StringUtils.isEmpty(hashValue)) {
                return new ResponseData<>(StringUtils.EMPTY, ErrorCode.ILLEGAL_INPUT);
            }
            return new ResponseData<>(hashValue, ErrorCode.SUCCESS);
        } catch (Exception e) {
            logger.error("Input Object type unsupported: {}", object.getClass().getName(), e);
            return new ResponseData<>(StringUtils.EMPTY, ErrorCode.ILLEGAL_INPUT);
        }
    }

    /**
     * todo 上传 Evidence Hash 到区块链的实际方法，在不同的区块链版本中有所不同。
     *
     * Actual method to upload to blockchain, varied in different blockchain versions.
     *
     * @param hashValue the hash value to be uploaded
     * @param privateKey the private key to reload contract and sign txn
     * @param extra the extra value (compact json formatted blob)
     */
    private ResponseData<String> hashToNewEvidence(String hashValue, String privateKey,
        String extra) {
        try {
            // 私钥对 Evidence Hash 的签名
            Sign.SignatureData sigData =
                DataToolUtils.signMessage(hashValue, privateKey);
            String signature = new String(
                DataToolUtils.base64Encode(DataToolUtils.simpleSignatureSerialization(sigData)),
                StandardCharsets.UTF_8);
            Long timestamp = DateUtils.getCurrentTimeStamp();

            boolean flag = getOfflineFlag();
            if (flag) {

                String[] args = new String[5];
                args[0] = hashValue;
                args[1] = signature;
                args[2] = extra;
                args[3] = String.valueOf(timestamp);
                args[4] = privateKey;
                String rawData = new StringBuffer()
                    .append(hashValue)
                    .append(signature)
                    .append(extra)
                    .append(timestamp)
                    .append(WeIdUtils.getWeIdFromPrivateKey(privateKey)).toString();
                String hash = DataToolUtils.sha3(rawData);
                String requestId = new BigInteger(hash.substring(2), 16).toString();
                boolean isSuccess = BatchTransactionUtils
                    .writeTransaction(requestId, "createEvidence", args, StringUtils.EMPTY);
                if (isSuccess) {
                    return new ResponseData<>(hashValue, ErrorCode.SUCCESS);
                } else {
                    return new ResponseData<>(hashValue, ErrorCode.OFFLINE_EVIDENCE_SAVE_FAILED);
                }
            }

            // 往 链上创建 Evidence
            return evidenceServiceEngine.createEvidence(
                hashValue,
                signature,
                extra,
                timestamp,
                privateKey
            );
        } catch (Exception e) {
            logger.error("create evidence failed due to system error. ", e);
            return new ResponseData<>(StringUtils.EMPTY, ErrorCode.CREDENTIAL_EVIDENCE_BASE_ERROR);
        }
    }

    /**
     * todo 根据传入的凭证存证hash值，在链上查找凭证在链上是否存在。
     *      如果存在，则返回所有为此hash值创建过存证的创建方，及其创建时间、额外信息。
     *
     * todo 获取 链上的 Evidence 数据
     * Get the evidence from blockchain.
     *
     * @param evidenceKey the evidence hash on chain  todo 链上的 Evidence Hash
     * @return The EvidenceInfo
     */
    @Override
    public ResponseData<EvidenceInfo> getEvidence(String evidenceKey) {

        // 先校验是否非法
        if (!DataToolUtils.isValidHash(evidenceKey)) {
            logger.error("Evidence argument illegal input: evidence hash. ");
            return new ResponseData<>(null, ErrorCode.ILLEGAL_INPUT);
        }
        try {

            // EvidenceHash  查询 Evidence信息
            return evidenceServiceEngine.getInfo(evidenceKey);
        } catch (Exception e) {
            logger.error("get evidence failed.", e);
            return new ResponseData<>(null, ErrorCode.CREDENTIAL_EVIDENCE_BASE_ERROR);
        }
    }

    private ResponseData<Boolean> verifySignatureToSigner(
        String rawData,
        String signerWeId,
        SignatureData signatureData
    ) {
        try {


            // 根据 WeId 查回 chain 上的 Document
            ResponseData<WeIdDocument> innerResponseData =
                weIdService.getWeIdDocument(signerWeId);
            if (innerResponseData.getErrorCode() != ErrorCode.SUCCESS.getCode()) {
                logger.error(
                    "Error occurred when fetching WeIdentity DID document for: {}, msg: {}",
                    signerWeId, innerResponseData.getErrorMessage());
                return new ResponseData<>(false, ErrorCode.CREDENTIAL_WEID_DOCUMENT_ILLEGAL);
            }
            WeIdDocument weIdDocument = innerResponseData.getResult();

            // 验签
            ErrorCode errorCode = DataToolUtils
                .verifySignatureFromWeId(rawData, signatureData, weIdDocument);
            if (errorCode.getCode() != ErrorCode.SUCCESS.getCode()) {
                return new ResponseData<>(false, errorCode);
            }
            return new ResponseData<>(true, ErrorCode.SUCCESS);
        } catch (Exception e) {
            logger.error("error occurred during verifying signatures from chain: ", e);
            return new ResponseData<>(false, ErrorCode.CREDENTIAL_EVIDENCE_BASE_ERROR);
        }
    }

    /**
     * todo 根据传入的存证信息和WeID，从链上根据WeID的公钥，判断此存证是否合法。
     *
     * Validate whether an evidence is signed by this WeID.
     *
     * @param evidenceInfo the evidence info fetched from chain
     * @param weId the WeID
     * @return true if yes, false otherwise
     */
    @Override
    public ResponseData<Boolean> verifySigner(EvidenceInfo evidenceInfo, String weId) {
        return verifySigner(evidenceInfo, weId, null);
    }


    /**
     *
     * todo 根据传入的存证信息和WeID，及传入的公钥，判断此WeID是否为存证的合法创建者。不需要链上交互.
     *
     * Validate whether an evidence is signed by this WeID with passed-in public key.
     *
     * @param evidenceInfo the evidence info fetched from chain
     * @param weId the WeID
     * @param publicKey the public key
     * @return true if yes, false otherwise
     */
    @Override
    public ResponseData<Boolean> verifySigner(
        EvidenceInfo evidenceInfo,
        String weId,
        String publicKey) {  // 入参的 publicKey 可以为 null

        // 入参非空、格式及合法性检查
        if (evidenceInfo == null || evidenceInfo.getSigners().isEmpty()) {
            return new ResponseData<>(false, ErrorCode.ILLEGAL_INPUT);
        }
        if (!WeIdUtils.isWeIdValid(weId)) {
            return new ResponseData<>(false, ErrorCode.WEID_INVALID);
        }
        if (!evidenceInfo.getSigners().contains(weId)) {
            logger.error("This Evidence does not contain the provided WeID: {}", weId);
            return new ResponseData<>(false, ErrorCode.WEID_DOES_NOT_EXIST);
        }

        // 查回当前 WeId 对该 Evidence 的signature
        EvidenceSignInfo signInfo = evidenceInfo.getSignInfo().get(weId);
        String signature = signInfo.getSignature();
        if (!DataToolUtils.isValidBase64String(signature)) {
            return new ResponseData<>(false, ErrorCode.CREDENTIAL_EVIDENCE_SIGNATURE_BROKEN);
        }

        SignatureData signatureData =
            DataToolUtils.simpleSignatureDeserialization(
                DataToolUtils.base64Decode(signature.getBytes(StandardCharsets.UTF_8))
            );

        // 如果 入参的 publicKey 为 null, 需要自己去 chain 上查回 WeId 对应的 Document
        // 根据存证中签名方信息，调用GetWeIdDocument()查询WeID公钥
        if (StringUtils.isEmpty(publicKey)) {
            //
            return verifySignatureToSigner(
                evidenceInfo.getCredentialHash(),
                WeIdUtils.convertAddressToWeId(weId),
                signatureData
            );
        } else {
            try {

                // 根据公钥 验签
                boolean result = DataToolUtils
                    .verifySignature(evidenceInfo.getCredentialHash(), signatureData,
                        new BigInteger(publicKey));
                if (!result) {
                    logger.error("Public key does not match signature.");
                    return new ResponseData<>(false, ErrorCode.CREDENTIAL_SIGNATURE_BROKEN);
                }
                return new ResponseData<>(true, ErrorCode.SUCCESS);
            } catch (Exception e) {
                logger.error("Passed-in signature illegal");
                return new ResponseData<>(false, ErrorCode.WEID_PUBLICKEY_INVALID);
            }
        }
    }

    // todo 将传入Object计算Hash值生成存证上链。
    //      此方法允许在创建存证时写入额外信息。
    //      额外信息为一个log记录，从后往前叠加存储。
    //      不同私钥发交易方的额外信息也是共存且相互独立存储的。
    //      如果您重复调用此接口，那么新写入的额外值会以列表的形式添加到之前的log列表之后。
    //      此方法还允许传入一个用户自定义的custom key (可能是一个 关键字)，用来查询链上的存证（而不是通过hash）。
    /* (non-Javadoc)
     * @see com.webank.weid.rpc.EvidenceService#createEvidenceWithLogAndCustomKey(
     * com.webank.weid.protocol.inf.Hashable, com.webank.weid.protocol.base.WeIdPrivateKey,
     * java.lang.String)
     */
    @Override
    public ResponseData<String> createEvidenceWithLogAndCustomKey(
        Hashable object,
        WeIdPrivateKey weIdPrivateKey,
        String log,
        String customKey) {
        if (StringUtils.isEmpty(customKey) || DataToolUtils.isValidHash(customKey)) {
            logger.error("Custom key must be non-empty and must not be of hash format.");
            return new ResponseData<>(StringUtils.EMPTY, ErrorCode.ILLEGAL_INPUT);
        }
        if (!DataToolUtils.isUtf8String(log)) {
            logger.error("Log format illegal.");
            return new ResponseData<>(StringUtils.EMPTY, ErrorCode.ILLEGAL_INPUT);
        }
        if (StringUtils.isEmpty(log)) {
            log = StringUtils.EMPTY;
        }
        if (!isChainStringLengthValid(log) || !isChainStringLengthValid(customKey)) {
            return new ResponseData<>(StringUtils.EMPTY, ErrorCode.ON_CHAIN_STRING_TOO_LONG);
        }
        if (StringUtils.isEmpty(customKey)) {
            customKey = StringUtils.EMPTY;
        }
        ResponseData<String> hashResp = getHashValue(object);
        String hashValue = hashResp.getResult();
        if (StringUtils.isEmpty(hashResp.getResult())) {
            return new ResponseData<>(StringUtils.EMPTY, hashResp.getErrorCode(),
                hashResp.getErrorMessage());
        }
        if (!WeIdUtils.isPrivateKeyValid(weIdPrivateKey)) {
            return new ResponseData<>(StringUtils.EMPTY,
                ErrorCode.CREDENTIAL_PRIVATE_KEY_NOT_EXISTS);
        }
        String privateKey = weIdPrivateKey.getPrivateKey();
        try {
            Sign.SignatureData sigData =
                DataToolUtils.signMessage(hashValue, privateKey);
            String signature = new String(
                DataToolUtils.base64Encode(DataToolUtils.simpleSignatureSerialization(sigData)),
                StandardCharsets.UTF_8);
            Long timestamp = DateUtils.getCurrentTimeStamp();

            boolean flag = getOfflineFlag();
            if (flag) {

                String[] args = new String[6];
                args[0] = hashValue;
                args[1] = signature;
                args[2] = log;
                args[3] = String.valueOf(timestamp);
                args[4] = customKey;
                args[5] = privateKey;
                String rawData = new StringBuffer()
                    .append(hashValue)
                    .append(signature)
                    .append(log)
                    .append(timestamp)
                    .append(customKey)
                    .append(WeIdUtils.getWeIdFromPrivateKey(privateKey)).toString();
                String hash = DataToolUtils.sha3(rawData);
                String requestId = new BigInteger(hash.substring(2), 16).toString();
                boolean isSuccess = BatchTransactionUtils
                    .writeTransaction(requestId, "createEvidenceWithCustomKey", args,
                        StringUtils.EMPTY);
                if (isSuccess) {
                    return new ResponseData<>(hashValue, ErrorCode.SUCCESS);
                } else {
                    return new ResponseData<>(hashValue, ErrorCode.OFFLINE_EVIDENCE_SAVE_FAILED);
                }
            }
            return evidenceServiceEngine.createEvidenceWithCustomKey(
                hashValue,
                signature,
                log,
                timestamp,
                customKey,
                privateKey
            );
        } catch (Exception e) {
            logger.error("create evidence failed due to system error. ", e);
            return new ResponseData<>(StringUtils.EMPTY, ErrorCode.CREDENTIAL_EVIDENCE_BASE_ERROR);
        }
    }

    // todo 根据传入的自定义索引，在链上查找凭证在链上是否存在。
    //      如果存在，则返回所有为此索引值值创建过存证的创建方，及其创建时间、额外信息。
    /* (non-Javadoc)
     * @see com.webank.weid.rpc.EvidenceService#getEvidenceByCustomKey(java.lang.String)
     */
    @Override
    public ResponseData<EvidenceInfo> getEvidenceByCustomKey(String customKey) {
        if (!isChainStringLengthValid(customKey)) {
            return new ResponseData<>(null, ErrorCode.ON_CHAIN_STRING_TOO_LONG);
        }
        try {
            return evidenceServiceEngine.getInfoByCustomKey(customKey);
        } catch (Exception e) {
            logger.error("get evidence failed.", e);
            return new ResponseData<>(null, ErrorCode.CREDENTIAL_EVIDENCE_BASE_ERROR);
        }
    }

    private boolean isChainStringLengthValid(String string) {
        return string.length() < WeIdConstant.ON_CHAIN_STRING_LENGTH;
    }

    private boolean getOfflineFlag() {
        String flag = PropertiesService.getInstance()
            .getProperty(ParamKeyConstant.ENABLE_OFFLINE);
        if (StringUtils.isNotBlank(flag)) {
            return new Boolean(flag);
        }
        return false;
    }
}
