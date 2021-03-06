/*
 *       Copyright漏 (2018-2019) WeBank Co., Ltd.
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

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.math.NumberUtils;
import org.bcos.web3j.crypto.ECKeyPair;
import org.bcos.web3j.crypto.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.webank.weid.constant.ErrorCode;
import com.webank.weid.constant.WeIdConstant;
import com.webank.weid.exception.LoadContractException;
import com.webank.weid.exception.PrivateKeyIllegalException;
import com.webank.weid.protocol.base.AuthenticationProperty;
import com.webank.weid.protocol.base.PublicKeyProperty;
import com.webank.weid.protocol.base.WeIdAuthentication;
import com.webank.weid.protocol.base.WeIdDocument;
import com.webank.weid.protocol.base.WeIdPrivateKey;
import com.webank.weid.protocol.base.WeIdPublicKey;
import com.webank.weid.protocol.request.AuthenticationArgs;
import com.webank.weid.protocol.request.CreateWeIdArgs;
import com.webank.weid.protocol.request.PublicKeyArgs;
import com.webank.weid.protocol.request.ServiceArgs;
import com.webank.weid.protocol.request.SetAuthenticationArgs;
import com.webank.weid.protocol.request.SetPublicKeyArgs;
import com.webank.weid.protocol.request.SetServiceArgs;
import com.webank.weid.protocol.response.CreateWeIdDataResult;
import com.webank.weid.protocol.response.ResponseData;
import com.webank.weid.rpc.WeIdService;
import com.webank.weid.util.WeIdUtils;

/**
 * TODO WeIdentity DID相关功能的核心接口
 *      本接口提供WeIdentity DID的创建、获取信息、设置属性等相关操作
 * Service implementations for operations on WeIdentity DID.
 *
 * @author tonychen 2018.10
 */
public class WeIdServiceImpl extends AbstractService implements WeIdService {

    /**
     * log4j object, for recording log.
     */
    private static final Logger logger = LoggerFactory.getLogger(WeIdServiceImpl.class);

    /**
     * todo 内部创建公私钥，并链上注册WeIdentity DID， 并返回公钥、私钥以及WeIdentity DID
     * Create a WeIdentity DID with null input param.
     *
     * @return the response data
     */
    @Override
    public ResponseData<CreateWeIdDataResult> createWeId() {

        CreateWeIdDataResult result = new CreateWeIdDataResult();
        ECKeyPair keyPair = null;

        try {
            // 本地 生成 公私钥对
            keyPair = Keys.createEcKeyPair();
        } catch (Exception e) {
            logger.error("Create weId failed.", e);
            return new ResponseData<>(null, ErrorCode.WEID_KEYPAIR_CREATE_FAILED);
        }

        String publicKey = String.valueOf(keyPair.getPublicKey());
        String privateKey = String.valueOf(keyPair.getPrivateKey());
        WeIdPublicKey userWeIdPublicKey = new WeIdPublicKey();
        userWeIdPublicKey.setPublicKey(publicKey);
        result.setUserWeIdPublicKey(userWeIdPublicKey);
        WeIdPrivateKey userWeIdPrivateKey = new WeIdPrivateKey();
        userWeIdPrivateKey.setPrivateKey(privateKey);
        result.setUserWeIdPrivateKey(userWeIdPrivateKey);
        String weId = WeIdUtils.convertPublicKeyToWeId(publicKey);
        result.setWeId(weId);

        // 根据 PubKey  PriKey  WeId 三者 上链
        ResponseData<Boolean> innerResp = processCreateWeId(weId, publicKey, privateKey, false);
        if (innerResp.getErrorCode() != ErrorCode.SUCCESS.getCode()) {
            logger.error(
                "[createWeId] Create weId failed. error message is :{}",
                innerResp.getErrorMessage()
            );
            return new ResponseData<>(null,
                ErrorCode.getTypeByErrorCode(innerResp.getErrorCode()),
                innerResp.getTransactionInfo());
        }
        return new ResponseData<>(result, ErrorCode.getTypeByErrorCode(innerResp.getErrorCode()),
            innerResp.getTransactionInfo());
    }

    /**
     *
     * todo 根据传入的公私钥，链上注册WeIdentity DID，并返回WeIdentity DID
     * Create a WeIdentity DID.
     *
     * @param createWeIdArgs the create WeIdentity DID args
     * @return the response data
     */
    @Override
    public ResponseData<String> createWeId(CreateWeIdArgs createWeIdArgs) {

        if (createWeIdArgs == null) {
            logger.error("[createWeId]: input parameter createWeIdArgs is null.");
            return new ResponseData<>(StringUtils.EMPTY, ErrorCode.ILLEGAL_INPUT);
        }
        if (!WeIdUtils.isPrivateKeyValid(createWeIdArgs.getWeIdPrivateKey()) || !WeIdUtils
            .isPrivateKeyLengthValid(createWeIdArgs.getWeIdPrivateKey().getPrivateKey())) {
            return new ResponseData<>(StringUtils.EMPTY, ErrorCode.WEID_PRIVATEKEY_INVALID);
        }
        String privateKey = createWeIdArgs.getWeIdPrivateKey().getPrivateKey();
        String publicKey = createWeIdArgs.getPublicKey();
        if (StringUtils.isNotBlank(publicKey)) {
            if (!WeIdUtils.isKeypairMatch(privateKey, publicKey)) {
                return new ResponseData<>(
                    StringUtils.EMPTY,
                    ErrorCode.WEID_PUBLICKEY_AND_PRIVATEKEY_NOT_MATCHED
                );
            }
            String weId = WeIdUtils.convertPublicKeyToWeId(publicKey);
            ResponseData<Boolean> isWeIdExistResp = this.isWeIdExist(weId);
            if (isWeIdExistResp.getResult() == null || isWeIdExistResp.getResult()) {
                logger
                    .error("[createWeId]: create weid failed, the weid :{} is already exist", weId);
                return new ResponseData<>(StringUtils.EMPTY, ErrorCode.WEID_ALREADY_EXIST);
            }
            ResponseData<Boolean> innerResp = processCreateWeId(weId, publicKey, privateKey, false);
            if (innerResp.getErrorCode() != ErrorCode.SUCCESS.getCode()) {
                logger.error(
                    "[createWeId]: create weid failed. error message is :{}, public key is {}",
                    innerResp.getErrorMessage(),
                    publicKey
                );
                return new ResponseData<>(StringUtils.EMPTY,
                    ErrorCode.getTypeByErrorCode(innerResp.getErrorCode()),
                    innerResp.getTransactionInfo());
            }
            return new ResponseData<>(weId,
                ErrorCode.getTypeByErrorCode(innerResp.getErrorCode()),
                innerResp.getTransactionInfo());
        } else {
            return new ResponseData<>(StringUtils.EMPTY, ErrorCode.WEID_PUBLICKEY_INVALID);
        }
    }

    /**
     * todo 查询Document详情  struct
     *      根据WeIdentity DID查询出WeIdentity DID Document对象
     * Get a WeIdentity DID Document.
     *
     * @param weId the WeIdentity DID
     * @return the WeIdentity DID document
     */
    @Override
    public ResponseData<WeIdDocument> getWeIdDocument(String weId) {

        if (!WeIdUtils.isWeIdValid(weId)) {
            logger.error("Input weId : {} is invalid.", weId);
            return new ResponseData<>(null, ErrorCode.WEID_INVALID);
        }

        // todo 去 chain 查询 Document 信息, 这里面包含的 "OBSOLETE"的publicKey 和 "OBSOLETEAUTH"的authentication
        ResponseData<WeIdDocument> weIdDocResp = weIdServiceEngine.getWeIdDocument(weId);
        if (weIdDocResp.getErrorCode() != ErrorCode.SUCCESS.getCode()) {
            return weIdDocResp;
        }
        return new ResponseData<>(trimObsoleteWeIdDocument(weIdDocResp.getResult()),
            weIdDocResp.getErrorCode(), weIdDocResp.getErrorMessage());
    }

    // TODO 清除掉 状态为 "失效的", 也就是 "OBSOLETE" 字样的 publicKey 和 auth
    private WeIdDocument trimObsoleteWeIdDocument(WeIdDocument originalDocument) {
        List<PublicKeyProperty> pubKeysToRemove = new ArrayList<>();
        List<AuthenticationProperty> authToRemove = new ArrayList<>();

        // 遍历, 如果 publicKey 为 "OBSOLETE", 则 从 publicKey List 中移除 publicKey
        for (PublicKeyProperty pr : originalDocument.getPublicKey()) {
            if (pr.getPublicKey().contains(WeIdConstant.REMOVED_PUBKEY_TAG)) {
                pubKeysToRemove.add(pr);

                // 且对应的  auth 也将清除
                for (AuthenticationProperty ap : originalDocument.getAuthentication()) {
                    if (ap.getPublicKey().equalsIgnoreCase(pr.getId())) {
                        authToRemove.add(ap);
                    }
                }
            }
        }

        // 遍历, 如果 auth 为 "OBSOLETEAUTH", 则 从 auth List 中移除 auth
        for (AuthenticationProperty ap : originalDocument.getAuthentication()) {
            if (ap.getPublicKey().contains(WeIdConstant.REMOVED_AUTHENTICATION_TAG)) {
                authToRemove.add(ap);
            }
        }
        originalDocument.getPublicKey().removeAll(pubKeysToRemove);
        originalDocument.getAuthentication().removeAll(authToRemove);
        return originalDocument;
    }

    /**
     *
     * todo 查询Document详情  jsonStr
     *      根据WeIdentity DID查询WeIdentity DID Document信息，并以JSON格式返回
     * Get a WeIdentity DID Document Json.
     *
     * @param weId the WeIdentity DID
     * @return the WeIdentity DID document json
     */
    @Override
    public ResponseData<String> getWeIdDocumentJson(String weId) {

        ResponseData<WeIdDocument> responseData = this.getWeIdDocument(weId);
        WeIdDocument result = responseData.getResult();

        if (result == null) {
            return new ResponseData<>(
                StringUtils.EMPTY,
                ErrorCode.getTypeByErrorCode(responseData.getErrorCode())
            );
        }
        ObjectMapper mapper = new ObjectMapper();
        String weIdDocument;
        try {
            weIdDocument = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(result);
        } catch (Exception e) {
            logger.error("write object to String fail.", e);
            return new ResponseData<>(
                StringUtils.EMPTY,
                ErrorCode.getTypeByErrorCode(responseData.getErrorCode())
            );
        }

        // 往 Document jsonStr 中 插入 @content 的k-v, 因为 Document 结构中并未定义这个东西
        weIdDocument =
            new StringBuffer()
                .append(weIdDocument)
                .insert(1, WeIdConstant.WEID_DOC_PROTOCOL_VERSION)
                .toString();

        ResponseData<String> responseDataJson = new ResponseData<String>();
        responseDataJson.setResult(weIdDocument);
        responseDataJson.setErrorCode(ErrorCode.getTypeByErrorCode(responseData.getErrorCode()));

        return responseDataJson;
    }

    /**
     * Remove a public key enlisted in WeID document together with the its authentication.
     *
     * @param setPublicKeyArgs the to-be-deleted publicKey
     * @return true if succeeds, false otherwise
     */
    @Override
    public ResponseData<Boolean> removePublicKeyWithAuthentication(
        SetPublicKeyArgs setPublicKeyArgs) {
        if (!verifySetPublicKeyArgs(setPublicKeyArgs)) {
            logger.error("[removePublicKey]: input parameter setPublicKeyArgs is illegal.");
            return new ResponseData<>(false, ErrorCode.ILLEGAL_INPUT);
        }
        if (!WeIdUtils.isPrivateKeyValid(setPublicKeyArgs.getUserWeIdPrivateKey())) {
            return new ResponseData<>(false, ErrorCode.WEID_PRIVATEKEY_INVALID);
        }

        String weId = setPublicKeyArgs.getWeId();
        ResponseData<WeIdDocument> responseData = this.getWeIdDocument(weId);
        if (responseData.getResult() == null) {
            return new ResponseData<>(false,
                ErrorCode.getTypeByErrorCode(responseData.getErrorCode())
            );
        }
        List<PublicKeyProperty> publicKeys = responseData.getResult().getPublicKey();
        for (PublicKeyProperty pk : publicKeys) {
            // TODO in future, add authorization check
            if (pk.getPublicKey().equalsIgnoreCase(setPublicKeyArgs.getPublicKey())) {
                // 如果 当前只剩下最后一个 public key 了, 则不可删除
                if (publicKeys.size() == 1) {
                    return new ResponseData<>(false,
                        ErrorCode.WEID_CANNOT_REMOVE_ITS_OWN_PUB_KEY_WITHOUT_BACKUP);
                }
            }
        }

        // Add correct tag by externally call removeAuthentication once
        SetAuthenticationArgs setAuthenticationArgs = new SetAuthenticationArgs();
        setAuthenticationArgs.setWeId(weId);
        WeIdPrivateKey weIdPrivateKey = new WeIdPrivateKey();
        weIdPrivateKey.setPrivateKey(setPublicKeyArgs.getUserWeIdPrivateKey().getPrivateKey());
        setAuthenticationArgs.setUserWeIdPrivateKey(weIdPrivateKey);
        setAuthenticationArgs.setPublicKey(setPublicKeyArgs.getPublicKey());
        setAuthenticationArgs.setOwner(setPublicKeyArgs.getOwner());

        // 先删除对应 publick 的 authentication
        ResponseData<Boolean> removeAuthResp = this.removeAuthentication(setAuthenticationArgs);
        if (!removeAuthResp.getResult()) {
            logger.error("Failed to remove authentication: " + removeAuthResp.getErrorMessage());
            return removeAuthResp;
        }

        String owner = setPublicKeyArgs.getOwner();
        String weAddress = WeIdUtils.convertWeIdToAddress(setPublicKeyArgs.getWeId());

        if (StringUtils.isEmpty(owner)) {
            owner = weAddress;
        } else {
            if (WeIdUtils.isWeIdValid(owner)) {
                owner = WeIdUtils.convertWeIdToAddress(owner);
            } else {
                logger.error("removePublicKey: owner : {} is invalid.", owner);
                return new ResponseData<>(false, ErrorCode.WEID_INVALID);
            }
        }
        try {
            String attributeKey =
                new StringBuffer()
                    .append(WeIdConstant.WEID_DOC_PUBLICKEY_PREFIX)
                    .append(WeIdConstant.SEPARATOR)
                    .append(setPublicKeyArgs.getType())
                    .append(WeIdConstant.SEPARATOR)
                    .append("base64")
                    .toString();
            String privateKey = setPublicKeyArgs.getUserWeIdPrivateKey().getPrivateKey();
            String publicKey = setPublicKeyArgs.getPublicKey();
            String attrValue = new StringBuffer()
                .append(publicKey)
                .append(WeIdConstant.REMOVED_PUBKEY_TAG).append("/") // 在 publick 上追加 `OBSOLETE` 就是 删除 piblic key 了
                .append(owner)
                .toString();

            // 然后在删除 publick key
            return weIdServiceEngine.setAttribute( // 设置 PubKey
                weAddress,
                attributeKey,
                attrValue,
                privateKey,
                false);
        } catch (PrivateKeyIllegalException e) {
            logger.error("[removePublicKey] set PublicKey failed because privateKey is illegal. ",
                e);
            return new ResponseData<>(false, e.getErrorCode());
        } catch (Exception e) {
            logger.error("[removePublicKey] set PublicKey failed with exception. ", e);
            return new ResponseData<>(false, ErrorCode.UNKNOW_ERROR);
        }
    }

    /**
     * todo 根据WeIdentity DID添加公钥
     * Set Public Key.
     *
     * @param setPublicKeyArgs the set public key args
     * @return the response data
     */
    @Override
    public ResponseData<Boolean> setPublicKey(SetPublicKeyArgs setPublicKeyArgs) {

        if (!verifySetPublicKeyArgs(setPublicKeyArgs)) {
            logger.error("[setPublicKey]: input parameter setPublicKeyArgs is illegal.");
            return new ResponseData<>(false, ErrorCode.ILLEGAL_INPUT);
        }
        if (!WeIdUtils.isPrivateKeyValid(setPublicKeyArgs.getUserWeIdPrivateKey())) {
            return new ResponseData<>(false, ErrorCode.WEID_PRIVATEKEY_INVALID);
        }

        String weId = setPublicKeyArgs.getWeId();
        String weAddress = WeIdUtils.convertWeIdToAddress(weId);
        if (StringUtils.isEmpty(weAddress)) {
            logger.error("setPublicKey: weId : {} is invalid.", weId);
            return new ResponseData<>(false, ErrorCode.WEID_INVALID);
        }
        ResponseData<Boolean> isWeIdExistResp = this.isWeIdExist(weId);
        if (isWeIdExistResp.getResult() == null || !isWeIdExistResp.getResult()) {
            logger.error("[SetPublicKey]: failed, the weid :{} does not exist", weId);
            return new ResponseData<>(false, ErrorCode.WEID_DOES_NOT_EXIST);
        }
        String owner = setPublicKeyArgs.getOwner();
        if (StringUtils.isEmpty(owner)) {
            owner = weAddress;
        } else {
            if (WeIdUtils.isWeIdValid(owner)) {
                owner = WeIdUtils.convertWeIdToAddress(owner);
            } else {
                logger.error("setPublicKey: owner : {} is invalid.", owner);
                return new ResponseData<>(false, ErrorCode.WEID_INVALID);
            }
        }
        String pubKey = setPublicKeyArgs.getPublicKey();

        String privateKey = setPublicKeyArgs.getUserWeIdPrivateKey().getPrivateKey();
        return processSetPubKey(
            setPublicKeyArgs.getType().getTypeName(),
            weAddress,
            owner,
            pubKey,
            privateKey,
            false);
    }


    /**
     * todo 根据WeIdentity DID添加Service信息
     * Set Service.
     *  设置 Service 信息
     * @param setServiceArgs the set service args
     * @return the response data
     */
    @Override
    public ResponseData<Boolean> setService(SetServiceArgs setServiceArgs) {
        if (!verifySetServiceArgs(setServiceArgs)) {
            logger.error("[setService]: input parameter setServiceArgs is illegal.");
            return new ResponseData<>(false, ErrorCode.ILLEGAL_INPUT);
        }
        if (!WeIdUtils.isPrivateKeyValid(setServiceArgs.getUserWeIdPrivateKey())) {
            return new ResponseData<>(false, ErrorCode.WEID_PRIVATEKEY_INVALID);
        }
        if (!verifyServiceType(setServiceArgs.getType())) {
            logger.error("[setService]: the length of service type is overlimit");
            return new ResponseData<>(false, ErrorCode.WEID_SERVICE_TYPE_OVERLIMIT);
        }
        String weId = setServiceArgs.getWeId();
        String serviceType = setServiceArgs.getType();
        String serviceEndpoint = setServiceArgs.getServiceEndpoint();
        return processSetService(
            setServiceArgs.getUserWeIdPrivateKey().getPrivateKey(),
            weId,
            serviceType,
            serviceEndpoint, // 这个可以就是个 URL
            false);

    }

    /**
     * todo 根据WeIdentity DID判断链上是否存在
     * Check if WeIdentity DID exists on Chain.
     *
     * @param weId the WeIdentity DID
     * @return true if exists, false otherwise
     */
    @Override
    public ResponseData<Boolean> isWeIdExist(String weId) {
        if (!WeIdUtils.isWeIdValid(weId)) {
            logger.error("[isWeIdExist] check weid failed. weid : {} is invalid.", weId);
            return new ResponseData<>(false, ErrorCode.WEID_INVALID);
        }
        return weIdServiceEngine.isWeIdExist(weId);
    }

    /**
     * todo 根据WeIdentity DID添加认证者
     * Set Authentication.
     *
     * @param setAuthenticationArgs the set authentication args
     * @return the response data
     */
    @Override
    public ResponseData<Boolean> setAuthentication(SetAuthenticationArgs setAuthenticationArgs) {

        if (!verifySetAuthenticationArgs(setAuthenticationArgs)) {
            logger.error("[setAuthentication]: input parameter setAuthenticationArgs is illegal.");
            return new ResponseData<>(false, ErrorCode.ILLEGAL_INPUT);
        }
        if (!WeIdUtils.isPrivateKeyValid(setAuthenticationArgs.getUserWeIdPrivateKey())) {
            return new ResponseData<>(false, ErrorCode.WEID_PRIVATEKEY_INVALID);
        }
        String weId = setAuthenticationArgs.getWeId();
        return processSetAuthentication(
            setAuthenticationArgs.getOwner(),
            setAuthenticationArgs.getPublicKey(),
            setAuthenticationArgs.getUserWeIdPrivateKey().getPrivateKey(),
            weId,
            false);
    }

    private ResponseData<Boolean> processSetAuthentication(
        String owner,
        String publicKey,
        String privateKey,
        String weId,
        boolean isDelegate) {
        if (WeIdUtils.isWeIdValid(weId)) {
            ResponseData<Boolean> isWeIdExistResp = this.isWeIdExist(weId);
            if (isWeIdExistResp.getResult() == null || !isWeIdExistResp.getResult()) {
                logger.error("[setAuthentication]: failed, the weid :{} does not exist",
                    weId);
                return new ResponseData<>(false, ErrorCode.WEID_DOES_NOT_EXIST);
            }
            String weAddress = WeIdUtils.convertWeIdToAddress(weId);
            if (StringUtils.isEmpty(owner)) {
                owner = weAddress;
            } else {
                if (WeIdUtils.isWeIdValid(owner)) {
                    owner = WeIdUtils.convertWeIdToAddress(owner);
                } else {
                    logger.error("[setAuthentication]: owner : {} is invalid.", owner);
                    return new ResponseData<>(false, ErrorCode.WEID_INVALID);
                }
            }
            try {
                String attrValue = new StringBuffer()
                    .append(publicKey)
                    .append(WeIdConstant.SEPARATOR)
                    .append(owner)
                    .toString();
                return weIdServiceEngine
                    .setAttribute( // 设置 认证方式
                            weAddress,
                        WeIdConstant.WEID_DOC_AUTHENTICATE_PREFIX,
                        attrValue,
                        privateKey,
                        isDelegate);
            } catch (PrivateKeyIllegalException e) {
                logger.error("Set authenticate with private key exception. Error message :{}", e);
                return new ResponseData<>(false, e.getErrorCode());
            } catch (Exception e) {
                logger.error("Set authenticate failed. Error message :{}", e);
                return new ResponseData<>(false, ErrorCode.UNKNOW_ERROR);
            }
        } else {
            logger.error("Set authenticate failed. weid : {} is invalid.", weId);
            return new ResponseData<>(false, ErrorCode.WEID_INVALID);
        }
    }

    /**
     * Remove an authentication tag in WeID document only - will not affect its public key.
     *
     * @param setAuthenticationArgs the to-be-deleted publicKey
     * @return true if succeeds, false otherwise
     */
    public ResponseData<Boolean> removeAuthentication(SetAuthenticationArgs setAuthenticationArgs) {

        if (!verifySetAuthenticationArgs(setAuthenticationArgs)) {
            logger
                .error("[removeAuthentication]: input parameter setAuthenticationArgs is illegal.");
            return new ResponseData<>(false, ErrorCode.ILLEGAL_INPUT);
        }
        if (!WeIdUtils.isPrivateKeyValid(setAuthenticationArgs.getUserWeIdPrivateKey())) {
            return new ResponseData<>(false, ErrorCode.WEID_PRIVATEKEY_INVALID);
        }
        String weId = setAuthenticationArgs.getWeId();
        if (WeIdUtils.isWeIdValid(weId)) {
            ResponseData<Boolean> isWeIdExistResp = this.isWeIdExist(weId);
            if (isWeIdExistResp.getResult() == null || !isWeIdExistResp.getResult()) {
                logger.error("[SetAuthentication]: failed, the weid :{} does not exist", weId);
                return new ResponseData<>(false, ErrorCode.WEID_DOES_NOT_EXIST);
            }
            String weAddress = WeIdUtils.convertWeIdToAddress(weId);

            String owner = setAuthenticationArgs.getOwner();
            if (StringUtils.isEmpty(owner)) {
                owner = weAddress;
            } else {
                if (WeIdUtils.isWeIdValid(owner)) {
                    owner = WeIdUtils.convertWeIdToAddress(owner);
                } else {
                    logger.error("[removeAuthentication]: owner : {} is invalid.", owner);
                    return new ResponseData<>(false, ErrorCode.WEID_INVALID);
                }
            }
            String privateKey = setAuthenticationArgs.getUserWeIdPrivateKey().getPrivateKey();
            try {
                String attrValue = new StringBuffer()
                    .append(setAuthenticationArgs.getPublicKey())
                    .append(WeIdConstant.REMOVED_AUTHENTICATION_TAG)   // 在 authentication 上追加 `OBSOLETEAUTH` 就是 删除 authentication 了
                    .append(WeIdConstant.SEPARATOR)
                    .append(owner)
                    .toString();
                return weIdServiceEngine
                    .setAttribute( // 设置认证方式
                            weAddress,
                        WeIdConstant.WEID_DOC_AUTHENTICATE_PREFIX,
                        attrValue,
                        privateKey,
                        false);
            } catch (PrivateKeyIllegalException e) {
                logger
                    .error("remove authenticate with private key exception. Error message :{}", e);
                return new ResponseData<>(false, e.getErrorCode());
            } catch (Exception e) {
                logger.error("remove authenticate failed. Error message :{}", e);
                return new ResponseData<>(false, ErrorCode.UNKNOW_ERROR);
            }
        } else {
            logger.error("Set authenticate failed. weid : {} is invalid.", weId);
            return new ResponseData<>(false, ErrorCode.WEID_INVALID);
        }
    }

    private boolean verifySetServiceArgs(SetServiceArgs setServiceArgs) {

        return !(setServiceArgs == null
            || StringUtils.isBlank(setServiceArgs.getType())
            || setServiceArgs.getUserWeIdPrivateKey() == null
            || StringUtils.isBlank(setServiceArgs.getServiceEndpoint()));
    }

    private boolean verifyServiceType(String type) {
        String serviceType = new StringBuffer()
            .append(WeIdConstant.WEID_DOC_SERVICE_PREFIX)
            .append(WeIdConstant.SEPARATOR)
            .append(type)
            .toString();
        int serviceTypeLength = serviceType.getBytes(StandardCharsets.UTF_8).length;
        return serviceTypeLength <= WeIdConstant.BYTES32_FIXED_LENGTH;
    }

    //  将 WeId / PubKey 注册到chain上
    private ResponseData<Boolean> processCreateWeId(
        String weId,
        String publicKey,
        String privateKey,
        boolean isDelegate) {

        String address = WeIdUtils.convertWeIdToAddress(weId);
        try {
            // 上链
            return weIdServiceEngine.createWeId(address, publicKey, privateKey, isDelegate);
        } catch (PrivateKeyIllegalException e) {
            logger.error("[createWeId] create weid failed because privateKey is illegal. ",
                e);
            return new ResponseData<>(false, e.getErrorCode());
        } catch (LoadContractException e) {
            logger.error("[createWeId] create weid failed because Load Contract with "
                    + "exception. ",
                e);
            return new ResponseData<>(false, e.getErrorCode());
        } catch (Exception e) {
            logger.error("[createWeId] create weid failed with exception. ", e);
            return new ResponseData<>(false, ErrorCode.UNKNOW_ERROR);
        }
    }

    private boolean verifySetPublicKeyArgs(SetPublicKeyArgs setPublicKeyArgs) {

        return !(setPublicKeyArgs == null
            || setPublicKeyArgs.getType() == null
            || setPublicKeyArgs.getUserWeIdPrivateKey() == null
            || StringUtils.isBlank(setPublicKeyArgs.getPublicKey()));
    }

    private boolean verifySetAuthenticationArgs(SetAuthenticationArgs setAuthenticationArgs) {

        return !(setAuthenticationArgs == null
            || setAuthenticationArgs.getUserWeIdPrivateKey() == null
            || StringUtils.isEmpty(setAuthenticationArgs.getPublicKey()));
    }

    // todo 根据传入的 PubKey 和 代理的PriKey，通过 代理发交易链上注册WeIdentity DID，并返回WeIdentity DID
    //      传入自己的WeIdentity DID及用作authentication的私钥 (可能是别人的 私钥, 但是是不是 在Document 中对应公钥的东西呢 ？？)
    /* (non-Javadoc)
     * @see com.webank.weid.rpc.WeIdService#delegateCreateWeId(
     * com.webank.weid.protocol.base.WeIdPublicKey,
     * com.webank.weid.protocol.base.WeIdAuthentication)
     */
    @Override
    public ResponseData<String> delegateCreateWeId(
        WeIdPublicKey publicKey,
        WeIdAuthentication weIdAuthentication) {

        if (publicKey == null || weIdAuthentication == null) {
            logger.error("[delegateCreateWeId]: input parameter is null.");
            return new ResponseData<>(StringUtils.EMPTY, ErrorCode.ILLEGAL_INPUT);
        }
        if (!WeIdUtils.isPrivateKeyValid(weIdAuthentication.getWeIdPrivateKey())) {
            return new ResponseData<>(StringUtils.EMPTY, ErrorCode.WEID_PRIVATEKEY_INVALID);
        }
        String privateKey = weIdAuthentication.getWeIdPrivateKey().getPrivateKey();
        String pubKey = publicKey.getPublicKey();
        if (StringUtils.isNotBlank(pubKey) && NumberUtils.isDigits(pubKey)) {
            String weId = WeIdUtils.convertPublicKeyToWeId(pubKey);
            ResponseData<Boolean> isWeIdExistResp = this.isWeIdExist(weId);
            if (isWeIdExistResp.getResult() == null || isWeIdExistResp.getResult()) {
                logger
                    .error(
                        "[delegateCreateWeId]: create weid failed, the weid :{} is already exist",
                        weId);
                return new ResponseData<>(StringUtils.EMPTY, ErrorCode.WEID_ALREADY_EXIST);
            }
            ResponseData<Boolean> innerResp = processCreateWeId(weId, pubKey, privateKey, true);
            if (innerResp.getErrorCode() != ErrorCode.SUCCESS.getCode()) {
                logger.error(
                    "[delegateCreateWeId]: create weid failed. error message is :{}, "
                        + "public key is {}",
                    innerResp.getErrorMessage(),
                    publicKey
                );
                return new ResponseData<>(StringUtils.EMPTY,
                    ErrorCode.getTypeByErrorCode(innerResp.getErrorCode()),
                    innerResp.getTransactionInfo());
            }
            return new ResponseData<>(weId,
                ErrorCode.getTypeByErrorCode(innerResp.getErrorCode()),
                innerResp.getTransactionInfo());
        } else {
            return new ResponseData<>(StringUtils.EMPTY, ErrorCode.WEID_PUBLICKEY_INVALID);
        }
    }

    // todo 由代理来给WeIdentity DID添加公钥
    /* (non-Javadoc)
     * @see com.webank.weid.rpc.WeIdService#delegateSetPublicKey(
     * com.webank.weid.protocol.request.PublicKeyArgs,
     * com.webank.weid.protocol.base.WeIdAuthentication)
     */
    @Override
    public ResponseData<Boolean> delegateSetPublicKey(
        PublicKeyArgs publicKeyArgs,
        WeIdAuthentication delegateAuth) {
        if (delegateAuth == null) {
            return new ResponseData<>(false, ErrorCode.ILLEGAL_INPUT);
        }
        if (publicKeyArgs == null || StringUtils.isEmpty(publicKeyArgs.getPublicKey())) {
            return new ResponseData<>(false, ErrorCode.WEID_PUBLICKEY_INVALID);
        }
        if (!WeIdUtils.isPrivateKeyValid(delegateAuth.getWeIdPrivateKey()) || !WeIdUtils
            .isPrivateKeyLengthValid(delegateAuth.getWeIdPrivateKey().getPrivateKey())) {
            return new ResponseData<>(false, ErrorCode.WEID_PRIVATEKEY_INVALID);
        }

        String weId = publicKeyArgs.getWeId();
        ResponseData<Boolean> isWeIdExistResp = this.isWeIdExist(weId);
        if (isWeIdExistResp.getResult() == null || !isWeIdExistResp.getResult()) {
            logger.error("[SetPublicKey]: failed, the weid :{} does not exist", weId);
            return new ResponseData<>(false, ErrorCode.WEID_DOES_NOT_EXIST);
        }
        String weAddress = WeIdUtils.convertWeIdToAddress(weId);
        if (StringUtils.isEmpty(weAddress)) {
            logger.error("setPublicKey: weId : {} is invalid.", weId);
            return new ResponseData<>(false, ErrorCode.WEID_INVALID);
        }
        String owner = publicKeyArgs.getOwner();
        if (StringUtils.isEmpty(owner)) {
            owner = weAddress;
        } else {
            if (WeIdUtils.isWeIdValid(owner)) {
                owner = WeIdUtils.convertWeIdToAddress(owner);
            } else {
                logger.error("setPublicKey: owner : {} is invalid.", owner);
                return new ResponseData<>(false, ErrorCode.WEID_INVALID);
            }
        }
        String pubKey = publicKeyArgs.getPublicKey();

        String privateKey = delegateAuth.getWeIdPrivateKey().getPrivateKey();

        return processSetPubKey(
            publicKeyArgs.getType().getTypeName(),
            weAddress,
            owner,
            pubKey,
            privateKey,
            true);
    }

    private ResponseData<Boolean> processSetPubKey(
        String type,
        String weAddress,
        String owner,
        String pubKey,
        String privateKey,
        boolean isDelegate) {

        try {
            String attributeKey =
                new StringBuffer()
                    .append(WeIdConstant.WEID_DOC_PUBLICKEY_PREFIX)
                    .append(WeIdConstant.SEPARATOR)
                    .append(type)
                    .append(WeIdConstant.SEPARATOR)
                    .append("base64")
                    .toString();
            String attrValue = new StringBuffer().append(pubKey).append("/").append(owner)
                .toString();
            return weIdServiceEngine.setAttribute( // 设置 PubKey
                weAddress,
                attributeKey,
                attrValue,
                privateKey,
                isDelegate);
        } catch (PrivateKeyIllegalException e) {
            logger.error("[setPublicKey] set PublicKey failed because privateKey is illegal. ",
                e);
            return new ResponseData<>(false, e.getErrorCode());
        } catch (Exception e) {
            logger.error("[setPublicKey] set PublicKey failed with exception. ", e);
            return new ResponseData<>(false, ErrorCode.UNKNOW_ERROR);
        }
    }

    // todo 根据WeIdentity DID添加Service信息
    /* (non-Javadoc)
     * @see com.webank.weid.rpc.WeIdService#delegateSetService(
     * com.webank.weid.protocol.request.SetServiceArgs,
     * com.webank.weid.protocol.base.WeIdAuthentication)
     */
    @Override
    public ResponseData<Boolean> delegateSetService(
        ServiceArgs serviceArgs,
        WeIdAuthentication delegateAuth) {
        if (delegateAuth == null) {
            return new ResponseData<>(false, ErrorCode.ILLEGAL_INPUT);
        }
        if (serviceArgs == null || StringUtils.isEmpty(serviceArgs.getServiceEndpoint())
            || !WeIdUtils.isWeIdValid(serviceArgs.getWeId())) {
            logger.error("[setService]: input parameter setServiceArgs is illegal.");
            return new ResponseData<>(false, ErrorCode.ILLEGAL_INPUT);
        }
        if (!WeIdUtils.isPrivateKeyValid(delegateAuth.getWeIdPrivateKey()) || !WeIdUtils
            .isPrivateKeyLengthValid(delegateAuth.getWeIdPrivateKey().getPrivateKey())) {
            return new ResponseData<>(false, ErrorCode.WEID_PRIVATEKEY_INVALID);
        }
        if (!verifyServiceType(serviceArgs.getType())) {
            logger.error("[setService]: the length of service type is overlimit");
            return new ResponseData<>(false, ErrorCode.WEID_SERVICE_TYPE_OVERLIMIT);
        }
        String weId = serviceArgs.getWeId();
        String serviceType = serviceArgs.getType();
        String serviceEndpoint = serviceArgs.getServiceEndpoint();
        return processSetService(
            delegateAuth.getWeIdPrivateKey().getPrivateKey(),
            weId,
            serviceType,
            serviceEndpoint,
            true);
    }

    // 将 service 信息 调用 WeIdContract 的 setAttribute() 存储链上
    private ResponseData<Boolean> processSetService(
        String privateKey,
        String weId,
        String serviceType,
        String serviceEndpoint,
        boolean isDelegate) {
        if (WeIdUtils.isWeIdValid(weId)) {
            // 调用 WeIdContract合约, 判断DID
            ResponseData<Boolean> isWeIdExistResp = this.isWeIdExist(weId);
            if (isWeIdExistResp.getResult() == null || !isWeIdExistResp.getResult()) {
                logger.error("[SetService]: failed, the weid :{} does not exist", weId);
                return new ResponseData<>(false, ErrorCode.WEID_DOES_NOT_EXIST);
            }
            try {
                String attributeKey = new StringBuffer()
                    .append(WeIdConstant.WEID_DOC_SERVICE_PREFIX)
                    .append(WeIdConstant.SEPARATOR)
                    .append(serviceType)
                    .toString();

                // 将 service 信息 调用 WeIdContract 的 setAttribute() 存储链上
                return weIdServiceEngine
                    .setAttribute( // 设置 service信息
                        WeIdUtils.convertWeIdToAddress(weId),
                        attributeKey,
                        serviceEndpoint,
                        privateKey,
                        isDelegate);

            } catch (PrivateKeyIllegalException e) {
                logger
                    .error("[setService] set PublicKey failed because privateKey is illegal. ",
                        e);
                return new ResponseData<>(false, e.getErrorCode());
            } catch (Exception e) {
                logger.error("[setService] set service failed. Error message :{}", e);
                return new ResponseData<>(false, ErrorCode.UNKNOW_ERROR);
            }
        } else {
            logger.error("[setService] set service failed, weid -->{} is invalid.", weId);
            return new ResponseData<>(false, ErrorCode.WEID_INVALID);
        }
    }

    // todo 根据WeIdentity DID添加认证者
    /* (non-Javadoc)
     * @see com.webank.weid.rpc.WeIdService#delegateSetAuthentication(
     * com.webank.weid.protocol.request.SetAuthenticationArgs,
     * com.webank.weid.protocol.base.WeIdAuthentication)
     */
    @Override
    public ResponseData<Boolean> delegateSetAuthentication(
        AuthenticationArgs authenticationArgs,
        WeIdAuthentication delegateAuth) {

        if (delegateAuth == null) {
            return new ResponseData<>(false, ErrorCode.ILLEGAL_INPUT);
        }
        if (authenticationArgs == null || !WeIdUtils.isWeIdValid(authenticationArgs.getWeId())
            || StringUtils.isEmpty(authenticationArgs.getPublicKey())) {
            return new ResponseData<>(false, ErrorCode.ILLEGAL_INPUT);
        }
        if (!WeIdUtils.isPrivateKeyValid(delegateAuth.getWeIdPrivateKey()) || !WeIdUtils
            .isPrivateKeyLengthValid(delegateAuth.getWeIdPrivateKey().getPrivateKey())) {
            return new ResponseData<>(false, ErrorCode.WEID_PRIVATEKEY_INVALID);
        }
        String weId = authenticationArgs.getWeId();
        return processSetAuthentication(
            authenticationArgs.getOwner(),
            authenticationArgs.getPublicKey(),
            delegateAuth.getWeIdPrivateKey().getPrivateKey(),
            weId,
            true);
    }
}
