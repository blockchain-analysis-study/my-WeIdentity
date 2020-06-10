/*
 *       Copyright© (2018-2019) WeBank Co., Ltd.
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

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.apache.commons.lang3.StringUtils;
import org.bcos.web3j.abi.datatypes.Address;
import org.bcos.web3j.crypto.ECKeyPair;
import org.bcos.web3j.crypto.Keys;
import org.bcos.web3j.crypto.Sign;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.webank.weid.constant.CredentialConstant;
import com.webank.weid.constant.CredentialFieldDisclosureValue;
import com.webank.weid.constant.ErrorCode;
import com.webank.weid.constant.ParamKeyConstant;
import com.webank.weid.exception.WeIdBaseException;
import com.webank.weid.protocol.base.Cpt;
import com.webank.weid.protocol.base.Credential;
import com.webank.weid.protocol.base.CredentialWrapper;
import com.webank.weid.protocol.base.WeIdDocument;
import com.webank.weid.protocol.base.WeIdPrivateKey;
import com.webank.weid.protocol.base.WeIdPublicKey;
import com.webank.weid.protocol.request.CreateCredentialArgs;
import com.webank.weid.protocol.response.ResponseData;
import com.webank.weid.rpc.CptService;
import com.webank.weid.rpc.CredentialService;
import com.webank.weid.rpc.WeIdService;
import com.webank.weid.service.BaseService;
import com.webank.weid.util.CredentialUtils;
import com.webank.weid.util.DataToolUtils;
import com.webank.weid.util.DateUtils;
import com.webank.weid.util.WeIdUtils;

/**
 * TODO 凭证签发相关功能的核心接口。 (后续都用 CredentialPojoServiceImpl)
 *
 * TODO 旧版的, 后续将作废
 *
 * todo 本接口提供凭证的签发和验证操作、Verifiable Presentation的签发和验证操作。
 * Service implementations for operations on Credential.
 *
 * @author chaoxinhu 2019.1
 */
public class CredentialServiceImpl extends BaseService implements CredentialService {

    private static final Logger logger = LoggerFactory.getLogger(CredentialServiceImpl.class);

    private CptService cptService = new CptServiceImpl();

    private WeIdService weIdService = new WeIdServiceImpl();


    /**
     * todo 创建电子凭证，默认是original类型，还支持轻量级lite1类型和基于零知识证明的zkp类型的credential
     *
     * todo 创建一个 Credential 的封装 (CredentialWrapper) 其中包含了 Credential 基础信息 和 disclosure 选择披露信息
     * Generate a credential.
     *
     *
     * {
     *      "claim":{
     *          "age":18,
     *          "gender":"F",
     *          "name":"zhangsan"
     *      },
     *      "context":"https://github.com/WeBankFinTech/WeIdentity/blob/master/context/v1",
     *      "cptId":2000082,
     *      "expirationDate":1588776752,
     *      "id":"0d633260-d31c-4155-b79d-a9eb67df7bab",
     *      "issuanceDate":1588065179,
     *      "issuer":"did:weid:101:0x9bd9897fcdb98428f7b152ce8a06cb16758ccd17",
     *      "proof":{
     *          "created":1588065179,
     *          "creator":"did:weid:101:0x9bd9897fcdb98428f7b152ce8a06cb16758ccd17#keys-0",
     *          "signatureValue":"G51huya0Q4Nz4HGa+dUju3GVrR0ng+atlXeouEKe60ImLMl6aihwZsSGExOgC8KwP3sUjeiggdba3xjVE9SSI/g=",
     *          "type":"Secp256k1"
     *      },
     *      "type":[
     *          "VerifiableCredential",
     *          "original"
     *      ]
     *  }
     *
     *
     *
     * @param args the args
     * @return the Credential response data
     */
    @Override
    public ResponseData<CredentialWrapper> createCredential(CreateCredentialArgs args) {

        CredentialWrapper credentialWrapper = new CredentialWrapper();
        try {
            ErrorCode innerResponse = checkCreateCredentialArgsValidity(args, true);
            if (ErrorCode.SUCCESS.getCode() != innerResponse.getCode()) {
                logger.error("Generate Credential input format error!");
                return new ResponseData<>(null, innerResponse);
            }

            Credential result = new Credential();
            String context = CredentialUtils.getDefaultCredentialContext();
            result.setContext(context);
            result.setId(UUID.randomUUID().toString());
            result.setCptId(args.getCptId());

            result.setIssuer(args.getIssuer());
            Long issuanceDate = args.getIssuanceDate();
            if (issuanceDate == null) {
                result.setIssuanceDate(DateUtils.getNoMillisecondTimeStamp());
            } else {
                Long newIssuanceDate =
                    DateUtils.convertToNoMillisecondTimeStamp(args.getIssuanceDate());
                if (newIssuanceDate == null) {
                    logger.error("Create Credential Args illegal.");
                    return new ResponseData<>(null, ErrorCode.CREDENTIAL_ISSUANCE_DATE_ILLEGAL);
                } else {
                    result.setIssuanceDate(newIssuanceDate);
                }
            }
            Long newExpirationDate =
                DateUtils.convertToNoMillisecondTimeStamp(args.getExpirationDate());
            if (newExpirationDate == null) {
                logger.error("Create Credential Args illegal.");
                return new ResponseData<>(null, ErrorCode.CREDENTIAL_EXPIRE_DATE_ILLEGAL);
            } else {
                result.setExpirationDate(newExpirationDate);
            }
            result.setClaim(args.getClaim());

            // 构建 选择性披露信息 disclosure (使用全部的 Claim信息生成 ？？)
            Map<String, Object> disclosureMap = new HashMap<>(args.getClaim());
            for (Map.Entry<String, Object> entry : disclosureMap.entrySet()) {
                disclosureMap.put(
                    entry.getKey(),
                    CredentialFieldDisclosureValue.DISCLOSED.getStatus()
                );
            }
            credentialWrapper.setDisclosure(disclosureMap);

            // Construct Credential Proof
            //
            // todo  生成 Credential 的 Proof
            Map<String, String> credentialProof = CredentialUtils.buildCredentialProof(
                result,
                args.getWeIdPrivateKey().getPrivateKey(),
                disclosureMap);
            result.setProof(credentialProof);

            credentialWrapper.setCredential(result);
            ResponseData<CredentialWrapper> responseData = new ResponseData<>(
                credentialWrapper,
                ErrorCode.SUCCESS
            );

            return responseData;
        } catch (Exception e) {
            logger.error("Generate Credential failed due to system error. ", e);
            return new ResponseData<>(null, ErrorCode.CREDENTIAL_ERROR);
        }
    }

    private boolean isMultiSignedCredential(Credential credential) {
        if (credential == null) {
            return false;
        }
        return (credential.getCptId() == CredentialConstant.CREDENTIAL_EMBEDDED_SIGNATURE_CPT
            .intValue());
    }

    /**
     *
     * todo 多签，在原凭证列表的基础上，创建包裹成一个新的多签凭证，由传入的私钥所签名。
     *      此凭证的CPT为一个固定值。在验证一个多签凭证时，会迭代验证其包裹的所有子凭证。
     *      本接口不支持创建选择性披露的多签凭证。
     *
     * Add an extra signer and signature to a Credential. Multiple signatures will be appended in an
     * embedded manner.
     *
     * todo 向凭据添加额外的签名者和签名。 多个签名将以嵌入方式添加
     *
     * @param credentialList original credential
     * @param weIdPrivateKey the passed-in privateKey and WeID bundle to sign
     * @return the modified CredentialWrapper
     */
    @Override
    public ResponseData<Credential> addSignature(
        List<Credential> credentialList,
        WeIdPrivateKey weIdPrivateKey) {
        if (credentialList == null || credentialList.size() == 0 || !WeIdUtils
            .isPrivateKeyValid(weIdPrivateKey)) {
            return new ResponseData<>(null, ErrorCode.ILLEGAL_INPUT);
        }
        Credential result = new Credential();
        result.setCptId(CredentialConstant.CREDENTIAL_EMBEDDED_SIGNATURE_CPT);
        result.setIssuanceDate(DateUtils.getNoMillisecondTimeStamp());
        result.setId(UUID.randomUUID().toString());
        result.setContext(CredentialUtils.getDefaultCredentialContext());
        Long expirationDate = 0L;
        for (Credential arg : credentialList) {
            if (arg.getExpirationDate() > expirationDate) {
                expirationDate = arg.getExpirationDate();
            }
        }
        Long newExpirationDate =
            DateUtils.convertToNoMillisecondTimeStamp(expirationDate);
        if (newExpirationDate == null) {
            logger.error("Create Credential Args illegal.");
            return new ResponseData<>(null, ErrorCode.CREDENTIAL_EXPIRE_DATE_ILLEGAL);
        } else {
            result.setExpirationDate(newExpirationDate);
        }
        String privateKey = weIdPrivateKey.getPrivateKey();
        ECKeyPair keyPair = ECKeyPair.create(new BigInteger(privateKey));
        String keyWeId = WeIdUtils
            .convertAddressToWeId(new Address(Keys.getAddress(keyPair)).toString());
        if (!weIdService.isWeIdExist(keyWeId).getResult()) {
            return new ResponseData<>(null, ErrorCode.WEID_DOES_NOT_EXIST);
        }
        result.setIssuer(keyWeId);

        // Check and remove duplicates in the credentialList
        List<Credential> trimmedCredentialList = new ArrayList<>();
        for (Credential arg : credentialList) {
            boolean found = false;
            for (Credential credAlive : trimmedCredentialList) {
                if (CredentialUtils.isEqual(arg, credAlive)) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                trimmedCredentialList.add(arg);
            }
        }

        Map<String, Object> claim = new HashMap<>();
        claim.put("credentialList", trimmedCredentialList);
        result.setClaim(claim);
        Map<String, String> credentialProof = CredentialUtils
            .buildCredentialProof(result, privateKey, null);
        result.setProof(credentialProof);
        return new ResponseData<>(result, ErrorCode.SUCCESS);
    }

    /**
     * Verify the validity of a credential without public key provided.
     *
     * @param credentialWrapper the credential wrapper.
     * @return the Boolean response data
     */
    @Override
    public ResponseData<Boolean> verify(CredentialWrapper credentialWrapper) {
        return verifyCredentialContent(credentialWrapper, null);
    }

    /**
     * todo 验证凭证是否正确
     * Verify Credential validity.
     */
    @Override
    public ResponseData<Boolean> verify(Credential credential) {

        // todo 因为需要校验, 所以 拿到的 Claim 中的 field 都必须是 Hash 字段
        //
        // 取出 Credential 中的 Claim, 生成一个 选择性披露 disclosureMap
        Map<String, Object> disclosureMap = new HashMap<>(credential.getClaim());
        // 遍历 disclosureMap 中的 各个 field
        for (Map.Entry<String, Object> entry : disclosureMap.entrySet()) {
            // 给 disclosureMap 中的 value 全改成 "0"
            disclosureMap.put(entry.getKey(), CredentialFieldDisclosureValue.DISCLOSED.getStatus());
        }

        // 现在外头 组装成一个 Credential Wrapper 封装
        CredentialWrapper credentialWrapper = new CredentialWrapper();

        // 设置 需要被校验的 Credential (可能是全披露的,  也可能是选择性披露的)
        credentialWrapper.setCredential(credential);

        // 设置 选择性披露的 k-v map
        credentialWrapper.setDisclosure(disclosureMap);

        // go ...
        return verifyCredentialContent(credentialWrapper, null);
    }

    /**
     * todo 验证凭证是否正确，需传入公钥
     * Verify the validity of a credential with public key provided.
     *
     * @param credentialWrapper the args
     * @param weIdPublicKey the specific public key to verify the credential.
     * @return the Boolean response data
     */
    @Override
    public ResponseData<Boolean> verifyCredentialWithSpecifiedPubKey(
        CredentialWrapper credentialWrapper,
        WeIdPublicKey weIdPublicKey) {
        if (credentialWrapper == null) {
            return new ResponseData<Boolean>(false, ErrorCode.ILLEGAL_INPUT);
        }
        if (weIdPublicKey == null) {
            return new ResponseData<Boolean>(false, ErrorCode.CREDENTIAL_ISSUER_MISMATCH);
        }
        return verifyCredentialContent(credentialWrapper, weIdPublicKey.getPublicKey());
    }

    /**
     * todo 传入Credential信息生成Credential整体的Hash值，一般在生成Evidence时调用
     * The only standardized inf to create a full Credential Hash for a given Credential.
     *
     * @param args the args
     * @return the Boolean response data
     */
    @Override
    public ResponseData<String> getCredentialHash(Credential args) {
        // 入参非空、格式及合法性检查
        ErrorCode innerResponse = CredentialUtils.isCredentialValid(args);
        if (ErrorCode.SUCCESS.getCode() != innerResponse.getCode()) {
            return new ResponseData<>(StringUtils.EMPTY, innerResponse);
        }

        // 返回凭证 Hash
        return new ResponseData<>(CredentialUtils.getCredentialHash(args), ErrorCode.SUCCESS);
    }

    /**
     * todo 传入Credential信息生成Credential整体的Hash值，一般在生成Evidence时调用
     *
     * Get the full hash value of a Credential with its selectively-disclosure map. All fields in
     * the Credential will be included. This method should be called when creating and verifying the
     * Credential Evidence and the result is selectively-disclosure irrelevant.
     *
     * todo  使用凭据的选择性公开 Map 获取凭据的完整哈希值.
     *       凭据中的所有字段都将包括在内.
     *       创建和验证凭据证据时应调用此方法, 并且结果与选择披露无关.
     *
     * @param credentialWrapper the args
     * @return the Credential Hash value in byte array, fixed to be 32 Bytes length
     */
    @Override
    public ResponseData<String> getCredentialHash(CredentialWrapper credentialWrapper) {
        if (credentialWrapper == null) {
            return new ResponseData<>(StringUtils.EMPTY, ErrorCode.ILLEGAL_INPUT);
        }
        if (credentialWrapper.getDisclosure() == null
            || credentialWrapper.getDisclosure().size() == 0) {
            return getCredentialHash(credentialWrapper.getCredential());
        }
        Credential credential = credentialWrapper.getCredential();
        ErrorCode innerResponse = CredentialUtils.isCredentialValid(credential);
        if (ErrorCode.SUCCESS.getCode() != innerResponse.getCode()) {
            return new ResponseData<>(StringUtils.EMPTY, innerResponse);
        }
        return new ResponseData<>(CredentialUtils.getCredentialWrapperHash(credentialWrapper),
            ErrorCode.SUCCESS);
    }

    // TODO 验证 Credential 主体 (其中 Claim 的字段可以是 全披露,  也可以是 选择性披露的)
    private ResponseData<Boolean> verifyCredentialContent(CredentialWrapper credentialWrapper,
        String publicKey) { // publicKey 字段可以存在, 也可以不存在

        // 取出 需要验证的 Credential
        Credential credential = credentialWrapper.getCredential();
        // todo 入参非空、格式及合法性检查
        ErrorCode innerResponse = CredentialUtils.isCredentialValid(credential);
        if (ErrorCode.SUCCESS.getCode() != innerResponse.getCode()) {
            logger.error("Credential input format error!");
            return new ResponseData<>(false, innerResponse);
        }
        if (credential.getCptId() == CredentialConstant.CREDENTIALPOJO_EMBEDDED_SIGNATURE_CPT
            .intValue()) {
            return new ResponseData<>(false, ErrorCode.CPT_ID_ILLEGAL);
        }
        if (credential.getCptId() == CredentialConstant.CREDENTIAL_EMBEDDED_SIGNATURE_CPT
            .intValue()) {
            // This is a multi-signed Credential, and its disclosure is against its leaf
            //
            // 这是一个多签名凭证，其披露违反了其规定
            Map<String, Object> disclosure = credentialWrapper.getDisclosure();
            // We firstly verify itself
            //
            // 我们首先验证自己
            credentialWrapper.setDisclosure(null);

            // 校验 单签名 Credential
            ResponseData<Boolean> innerResp = verifySingleSignedCredential(credentialWrapper,
                publicKey);
            if (!innerResp.getResult()) {
                return new ResponseData<>(false, innerResp.getErrorCode(),
                    innerResp.getErrorMessage());
            }
            // Then, we verify its list members one-by-one
            //
            // 然后，我们逐一验证其列表成员
            credentialWrapper.setDisclosure(disclosure);
            List<Credential> innerCredentialList;
            try {
                if (credentialWrapper.getCredential().getClaim()
                    .get("credentialList") instanceof String) {
                    // For selectively-disclosed credential, just skip - external check is enough
                    //
                    // 对于有选择地公开的凭证，只需跳过-外部检查就足够了
                    return new ResponseData<>(true, ErrorCode.SUCCESS);
                } else {
                    innerCredentialList = (ArrayList) credentialWrapper.getCredential().getClaim()
                        .get("credentialList");
                }
            } catch (Exception e) {
                return new ResponseData<>(false, ErrorCode.CREDENTIAL_CLAIM_DATA_ILLEGAL);
            }
            for (Credential innerCredential : innerCredentialList) {
                credentialWrapper.setCredential(innerCredential);
                // Make sure that this disclosure is a meaningful one
                //
                // 确保这项披露是有意义的
                if (disclosure != null && disclosure.size() <= 1
                    && disclosure.size() != innerCredential.getClaim().size()
                    && disclosure.containsKey("credentialList")) {
                    credentialWrapper.setDisclosure(null);
                }
                if (disclosure == null) {
                    credentialWrapper.setDisclosure(null);
                }

                // todo 递归
                innerResp = verifyCredentialContent(credentialWrapper, publicKey);
                if (!innerResp.getResult()) {
                    return new ResponseData<>(false, innerResp.getErrorCode(),
                        innerResp.getErrorMessage());
                }
            }
            return new ResponseData<>(true, ErrorCode.SUCCESS);
        }
        // 校验 单签名 Credential
        return verifySingleSignedCredential(credentialWrapper, publicKey);
    }

    // todo 校验 单签名 Credential (目前 是有 单签凭证 ??  虽然 系统 cpt106 和 cpt107 是 支持多签的)
    private ResponseData<Boolean> verifySingleSignedCredential(CredentialWrapper credentialWrapper,
        String publicKey) {
        Credential credential = credentialWrapper.getCredential();
        // 校验 issyer 的 WeId 是否存在
        ResponseData<Boolean> responseData = verifyIssuerExistence(credential.getIssuer());
        if (!responseData.getResult()) {
            return responseData;
        }

        // 查询CPT存在性及Claim关联语义
        // 调用智能合约，查询CPT
        // CPT格式要求
        ErrorCode errorCode = verifyCptFormat(
            credential.getCptId(),
            credential.getClaim()
        );
        if (ErrorCode.SUCCESS.getCode() != errorCode.getCode()) {
            return new ResponseData<>(false, errorCode);
        }

        // 验证过期、撤销与否
        responseData = verifyNotExpired(credential);
        if (!responseData.getResult()) {
            return responseData;
        }
        // 通过公钥与签名对比，验证Issuer是否签发此凭证
        // publicKey 可能为 null
        // 这时候需要先 调用智能合约，查询Issuer的WeIdentity DID Document
        // 获取 publicKey
        responseData = verifySignature(credentialWrapper, publicKey);
        return responseData;
    }

    private ErrorCode checkCreateCredentialArgsValidity(
        CreateCredentialArgs args, boolean privateKeyRequired) {
        ErrorCode innerResponseData = CredentialUtils.isCreateCredentialArgsValid(args);
        if (ErrorCode.SUCCESS.getCode() != innerResponseData.getCode()) {
            logger.error("Create Credential Args illegal: {}", innerResponseData.getCodeDesc());
            return innerResponseData;
        }
        if (privateKeyRequired
            && StringUtils.isEmpty(args.getWeIdPrivateKey().getPrivateKey())) {
            logger.error(ErrorCode.CREDENTIAL_PRIVATE_KEY_NOT_EXISTS.getCodeDesc());
            return ErrorCode.CREDENTIAL_PRIVATE_KEY_NOT_EXISTS;
        }
        return ErrorCode.SUCCESS;
    }


    // 校验 issyer 的 WeId 是否存在
    private ResponseData<Boolean> verifyIssuerExistence(String issuerWeId) {
        ResponseData<Boolean> responseData = weIdService.isWeIdExist(issuerWeId);
        if (responseData == null || !responseData.getResult()) {
            return new ResponseData<>(false, ErrorCode.CREDENTIAL_ISSUER_NOT_EXISTS);
        }
        return responseData;
    }

    private ErrorCode verifyCptFormat(Integer cptId, Map<String, Object> claim) {
        if (cptId == CredentialConstant.CREDENTIAL_EMBEDDED_SIGNATURE_CPT.intValue()) {
            if (!claim.containsKey("credentialList")) {
                return ErrorCode.CREDENTIAL_CLAIM_DATA_ILLEGAL;
            } else {
                return ErrorCode.SUCCESS;
            }
        }
        try {
            //String claimStr = JsonUtil.objToJsonStr(claim);
            String claimStr = DataToolUtils.serialize(claim);
            Cpt cpt = cptService.queryCpt(cptId).getResult();
            if (cpt == null) {
                logger.error(ErrorCode.CREDENTIAL_CPT_NOT_EXISTS.getCodeDesc());
                return ErrorCode.CREDENTIAL_CPT_NOT_EXISTS;
            }
            //String cptJsonSchema = JsonUtil.objToJsonStr(cpt.getCptJsonSchema());
            String cptJsonSchema = DataToolUtils.serialize(cpt.getCptJsonSchema());

            if (!DataToolUtils.isCptJsonSchemaValid(cptJsonSchema)) {
                logger.error(ErrorCode.CPT_JSON_SCHEMA_INVALID.getCodeDesc());
                return ErrorCode.CPT_JSON_SCHEMA_INVALID;
            }
            if (!DataToolUtils.isValidateJsonVersusSchema(claimStr, cptJsonSchema)) {
                logger.error(ErrorCode.CREDENTIAL_CLAIM_DATA_ILLEGAL.getCodeDesc());
                return ErrorCode.CREDENTIAL_CLAIM_DATA_ILLEGAL;
            }
            return ErrorCode.SUCCESS;
        } catch (Exception e) {
            logger.error(
                "Generic error occurred during verify cpt format when verifyCredential: " + e);
            return ErrorCode.CREDENTIAL_ERROR;
        }
    }

    private ResponseData<Boolean> verifyNotExpired(Credential credential) {
        try {
            boolean result = DateUtils.isAfterCurrentTime(credential.getExpirationDate());
            ResponseData<Boolean> responseData = new ResponseData<>(result, ErrorCode.SUCCESS);
            if (!result) {
                responseData.setErrorCode(ErrorCode.CREDENTIAL_EXPIRED);
            }
            return responseData;
        } catch (Exception e) {
            logger.error(
                "Generic error occurred during verify expiration when verifyCredential: " + e);
            return new ResponseData<>(false, ErrorCode.CREDENTIAL_ERROR);
        }
    }

    // 校验 签名
    // 通过公钥与签名对比，验证Issuer是否签发此凭证
    //
    // publicKey 可能为 null
    // 这时候需要先 调用智能合约，查询Issuer的WeIdentity DID Document
    // 获取 publicKey
    private ResponseData<Boolean> verifySignature(
        CredentialWrapper credentialWrapper,
        String publicKey) { // publicKey 可以为 null

        try {
            // 取出需要 验证的 Credential 信息 (字段可以使全披露的/ 也可以是选择性披露的)
            Credential credential = credentialWrapper.getCredential();
            // 取出 选择性披露 field 要求
            Map<String, Object> disclosureMap = credentialWrapper.getDisclosure();

            // 计算 credential 字段的Hash  todo (妈的, 这里为什么 不加salt算Hash ??)
            String rawData = CredentialUtils
                .getCredentialThumbprintWithoutSig(credential, disclosureMap);

            // todo 提取出 proof 中的 signatureValue 字段的值
            Sign.SignatureData signatureData =
                DataToolUtils.simpleSignatureDeserialization(
                    DataToolUtils.base64Decode(
                        credential.getSignature().getBytes(StandardCharsets.UTF_8)
                    )
                );

            // 如果 入参的 PublicKey 为 null, 则需要我们自己去 查对应 WeId 的Document 中的 publicKey
            if (StringUtils.isEmpty(publicKey)) {
                // Fetch public key from chain
                String credentialIssuer = credential.getIssuer();
                ResponseData<WeIdDocument> innerResponseData =
                    weIdService.getWeIdDocument(credentialIssuer);
                if (innerResponseData.getErrorCode() != ErrorCode.SUCCESS.getCode()) {
                    logger.error(
                        "Error occurred when fetching WeIdentity DID document for: {}, msg: {}",
                        credentialIssuer, innerResponseData.getErrorMessage());
                    return new ResponseData<>(false, ErrorCode.CREDENTIAL_WEID_DOCUMENT_ILLEGAL);
                } else {
                    // todo 使用 Document 和 获取的 Claim Sha3 Hash 和 签名 去做验签
                    WeIdDocument weIdDocument = innerResponseData.getResult();
                    ErrorCode errorCode = DataToolUtils
                        .verifySignatureFromWeId(rawData, signatureData, weIdDocument);
                    if (errorCode.getCode() != ErrorCode.SUCCESS.getCode()) {
                        return new ResponseData<>(false, errorCode);
                    }
                    return new ResponseData<>(true, ErrorCode.SUCCESS);
                }
            } else {

                // 如果有 公钥, 则直接去做 验签
                boolean result =
                    DataToolUtils
                        .verifySignature(rawData, signatureData, new BigInteger(publicKey));
                if (!result) {
                    return new ResponseData<>(false, ErrorCode.CREDENTIAL_SIGNATURE_BROKEN);
                }
                return new ResponseData<>(true, ErrorCode.SUCCESS);
            }
        } catch (SignatureException e) {
            logger.error(
                "Generic signatureException occurred during verify signature "
                    + "when verifyCredential: ", e);
            return new ResponseData<>(false, ErrorCode.CREDENTIAL_EXCEPTION_VERIFYSIGNATURE);
        } catch (WeIdBaseException e) {
            logger.error(
                "Generic signatureException occurred during verify signature ", e);
            return new ResponseData<>(false, ErrorCode.CREDENTIAL_SIGNATURE_BROKEN);
        } catch (Exception e) {
            logger.error(
                "Generic exception occurred during verify signature when verifyCredential: ", e);
            return new ResponseData<>(false, ErrorCode.CREDENTIAL_ERROR);
        }
    }

    /**
     * Generate a credential with selected data.
     *
     * @param credential the credential
     * @param disclosure the keys which select to disclosure
     * @return credential
     */
    @Override
    public ResponseData<CredentialWrapper> createSelectiveCredential(
        Credential credential,
        String disclosure) {

        //setp 1: check if the input args is illegal.
        CredentialWrapper credentialResult = new CredentialWrapper();
        ErrorCode checkResp = CredentialUtils.isCredentialValid(credential);
        if (ErrorCode.SUCCESS.getCode() != checkResp.getCode()) {
            return new ResponseData<>(credentialResult, checkResp);
        }
        if (isMultiSignedCredential(credential)) {
            return new ResponseData<>(credentialResult, ErrorCode.CPT_ID_ILLEGAL);
        }

        //step 2: convet values of claim to hash by disclosure status
        Map<String, Object> claim = credential.getClaim();
        Map<String, Object> hashMap = new HashMap<String, Object>(claim);

        for (Map.Entry<String, Object> entry : claim.entrySet()) {
            claim.put(entry.getKey(), CredentialUtils.getFieldHash(entry.getValue()));
        }
        Map<String, Object> disclosureMap = DataToolUtils.deserialize(disclosure, HashMap.class);

        for (Map.Entry<String, Object> entry : disclosureMap.entrySet()) {
            if (CredentialFieldDisclosureValue.DISCLOSED.getStatus()
                .equals(entry.getValue())) {
                claim.put(entry.getKey(), hashMap.get(entry.getKey()));
            }
        }

        // step 3: build response of selective credential to caller.
        credentialResult.setCredential(credential);
        credentialResult.setDisclosure(disclosureMap);

        return new ResponseData<>(credentialResult, ErrorCode.SUCCESS);
    }

    /**
     * Get the Json String of a Credential. All fields in the Credential will be included. This also
     * supports the selectively disclosed Credential.
     *
     * @param credential the credential wrapper
     * @return the Credential Json value in String
     */
    @Override
    public ResponseData<String> getCredentialJson(Credential credential) {
        ErrorCode errorCode = CredentialUtils.isCredentialValid(credential);
        if (errorCode.getCode() != ErrorCode.SUCCESS.getCode()) {
            return new ResponseData<>(
                StringUtils.EMPTY,
                ErrorCode.getTypeByErrorCode(errorCode.getCode())
            );
        }
        // Convert timestamp into UTC timezone
        try {
            Map<String, Object> credMap = DataToolUtils.objToMap(credential);
            String issuanceDate = DateUtils.convertTimestampToUtc(credential.getIssuanceDate());
            String expirationDate = DateUtils.convertTimestampToUtc(credential.getExpirationDate());
            credMap.put(ParamKeyConstant.ISSUANCE_DATE, issuanceDate);
            credMap.put(ParamKeyConstant.EXPIRATION_DATE, expirationDate);
            credMap.remove(ParamKeyConstant.CONTEXT);
            credMap.put(CredentialConstant.CREDENTIAL_CONTEXT_PORTABLE_JSON_FIELD,
                CredentialConstant.DEFAULT_CREDENTIAL_CONTEXT);
            String credentialString = DataToolUtils.mapToCompactJson(credMap);
            return new ResponseData<>(credentialString, ErrorCode.SUCCESS);
        } catch (Exception e) {
            logger.error("Json conversion failed in getCredentialJson: ", e);
            return new ResponseData<>(StringUtils.EMPTY, ErrorCode.CREDENTIAL_ERROR);
        }
    }
}
