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
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.webank.weid.constant.ErrorCode;
import com.webank.weid.constant.WeIdConstant;
import com.webank.weid.protocol.base.AuthorityIssuer;
import com.webank.weid.protocol.base.WeIdAuthentication;
import com.webank.weid.protocol.request.RegisterAuthorityIssuerArgs;
import com.webank.weid.protocol.request.RemoveAuthorityIssuerArgs;
import com.webank.weid.protocol.response.ResponseData;
import com.webank.weid.rpc.AuthorityIssuerService;
import com.webank.weid.rpc.WeIdService;
import com.webank.weid.util.WeIdUtils;

/**
 * todo 在WeIdentity的整体架构中，存在着可信的“授权机构”这一角色。
 *      一般来说，授权机构特指那些广为人知的、具有一定公信力的、并且有相对频繁签发Credential需求的实体。
 *
 * todo 本接口提供了对这类授权签发Credential的机构的注册、移除、查询信息等操作
 * Service implementations for operations on Authority Issuer.
 *
 * @author chaoxinhu 2018.10
 */
public class AuthorityIssuerServiceImpl extends AbstractService implements AuthorityIssuerService {

    private static final Logger logger = LoggerFactory
        .getLogger(AuthorityIssuerServiceImpl.class);

    private WeIdService weIdService = new WeIdServiceImpl();

    /**
     * todo 这是一个需要权限的操作，目前只有合约的部署者（一般为SDK）才能正确执行
     * Register a new Authority Issuer on Chain.
     *
     * @param args the args
     * @return the Boolean response data
     */
    @Override
    public ResponseData<Boolean> registerAuthorityIssuer(RegisterAuthorityIssuerArgs args) {

        ErrorCode innerResponseData = checkRegisterAuthorityIssuerArgs(args);
        if (ErrorCode.SUCCESS.getCode() != innerResponseData.getCode()) {
            return new ResponseData<>(false, innerResponseData);
        }
        try {
            return authEngine.addAuthorityIssuer(args);
        } catch (Exception e) {
            logger.error("register has error, Error Message:{}", e);
            return new ResponseData<>(false, ErrorCode.AUTHORITY_ISSUER_ERROR);
        }
    }

    /**
     * todo 这是一个需要权限的操作，目前只有合约的部署者（一般为SDK）才能正确执行
     * Remove a new Authority Issuer on Chain.
     *
     * @param args the args
     * @return the Boolean response data
     */
    @Override
    public ResponseData<Boolean> removeAuthorityIssuer(RemoveAuthorityIssuerArgs args) {

        ErrorCode innerResponseData = checkRemoveAuthorityIssuerArgs(args);
        if (ErrorCode.SUCCESS.getCode() != innerResponseData.getCode()) {
            return new ResponseData<>(false, innerResponseData);
        }

        try {
            return authEngine.removeAuthorityIssuer(args);
        } catch (Exception e) {
            logger.error("remove authority issuer failed.", e);
            return new ResponseData<>(false, ErrorCode.AUTHORITY_ISSUER_ERROR);
        }
    }

    /**
     * todo 根据WeIdentity DID判断是否为权威机构
     * Check whether the given weId is an authority issuer.
     *
     * @param weId the WeIdentity DID
     * @return the Boolean response data
     */
    @Override
    public ResponseData<Boolean> isAuthorityIssuer(String weId) {

        if (!WeIdUtils.isWeIdValid(weId)) {
            return new ResponseData<>(false, ErrorCode.WEID_INVALID);
        }
        String addr = WeIdUtils.convertWeIdToAddress(weId);
        try {
            return authEngine.isAuthorityIssuer(addr);
        } catch (Exception e) {
            logger.error("check authority issuer id failed.", e);
            return new ResponseData<>(false, ErrorCode.AUTHORITY_ISSUER_ERROR);
        }
    }

    /**
     * todo 根据WeIdentity DID查询权威机构信息
     * Query the authority issuer information given weId.
     *
     * @param weId the WeIdentity DID
     * @return the AuthorityIssuer response data
     */
    @Override
    public ResponseData<AuthorityIssuer> queryAuthorityIssuerInfo(String weId) {
        if (!WeIdUtils.isWeIdValid(weId)) {
            return new ResponseData<>(null, ErrorCode.WEID_INVALID);
        }
        try {
            return authEngine.getAuthorityIssuerInfoNonAccValue(weId);
        } catch (Exception e) {
            logger.error("query authority issuer failed.", e);
            return new ResponseData<>(null, ErrorCode.AUTHORITY_ISSUER_ERROR);
        }
    }

    /**
     * todo 查询指定范围内的issuer列表
     * Get all of the authority issuer.
     *
     * @param index start position
     * @param num number of returned authority issuer in this request
     * @return Execution result
     */
    @Override
    public ResponseData<List<AuthorityIssuer>> getAllAuthorityIssuerList(Integer index,
        Integer num) {
        ErrorCode errorCode = isStartEndPosValid(index, num);
        if (errorCode.getCode() != ErrorCode.SUCCESS.getCode()) {
            return new ResponseData<>(null, errorCode);
        }
        try {
            List<String> addrList = authEngine.getAuthorityIssuerAddressList(index, num);
            List<AuthorityIssuer> authorityIssuerList = new ArrayList<>();
            for (String address : addrList) {
                String weId = WeIdUtils.convertAddressToWeId(address);
                ResponseData<AuthorityIssuer> innerResponseData
                    = this.queryAuthorityIssuerInfo(weId);
                if (innerResponseData.getResult() != null) {
                    authorityIssuerList.add(innerResponseData.getResult());
                }
            }
            return new ResponseData<>(authorityIssuerList, ErrorCode.SUCCESS);
        } catch (Exception e) {
            logger.error("query authority issuer list failed.", e);
            return new ResponseData<>(null, ErrorCode.AUTHORITY_ISSUER_ERROR);
        }
    }

    /**
     * todo 指定并注册不同issuer的类型，如学校、政府机构等
     * todo 本方法对传入的WeIdAuthentication没有特定权限要求
     * 注册一个新的 发行者的 类型
     * Register a new issuer type.
     *
     * @param callerAuth the caller
     * @param issuerType the specified issuer type
     * @return Execution result
     */
    public ResponseData<Boolean> registerIssuerType(
        WeIdAuthentication callerAuth,          // 调用者的  WeId, PriKey, PubKey
        String issuerType                       // 新的 发行者类型
    ) {
        ErrorCode innerCode = isIssuerTypeValid(issuerType);
        if (innerCode != ErrorCode.SUCCESS) {
            return new ResponseData<>(false, innerCode);
        }
        innerCode = isCallerAuthValid(callerAuth);
        if (innerCode != ErrorCode.SUCCESS) {
            return new ResponseData<>(false, innerCode);
        }
        try {

            // 注册新的 发行者类型
            return authEngine
                .registerIssuerType(issuerType, callerAuth.getWeIdPrivateKey().getPrivateKey());
        } catch (Exception e) {
            logger.error("register issuer type failed.", e);
            return new ResponseData<>(false, ErrorCode.AUTHORITY_ISSUER_ERROR);
        }
    }


    /**
     * todo 向指定的issuerType中添加成员
     *      方法的调用者至少需要是Authority Issuer才能成功
     * Marked an issuer as the specified issuer type.
     *
     * @param callerAuth the caller who have the access to modify this list
     * @param issuerType the specified issuer type
     * @param targetIssuerWeId the weId of the issuer who will be marked as a specific issuer type
     * @return Execution result
     */
    public ResponseData<Boolean> addIssuerIntoIssuerType(
        WeIdAuthentication callerAuth,
        String issuerType,
        String targetIssuerWeId
    ) {
        ErrorCode innerCode = isSpecificTypeIssuerArgsValid(callerAuth, issuerType,
            targetIssuerWeId);
        if (innerCode != ErrorCode.SUCCESS) {
            return new ResponseData<>(false, innerCode);
        }
        try {
            String issuerAddress = WeIdUtils.convertWeIdToAddress(targetIssuerWeId);
            return authEngine.addIssuer(issuerType, issuerAddress,
                callerAuth.getWeIdPrivateKey().getPrivateKey());
        } catch (Exception e) {
            logger.error("add issuer into type failed.", e);
            return new ResponseData<>(false, ErrorCode.AUTHORITY_ISSUER_ERROR);
        }
    }

    /**
     * todo 移除指定issuerType里面的WeId成员
     * Removed an issuer from the specified issuer list.
     *
     * @param callerAuth the caller who have the access to modify this list
     * @param issuerType the specified issuer type
     * @param targetIssuerWeId the weId of the issuer to be removed from a specific issuer list
     * @return Execution result
     */
    public ResponseData<Boolean> removeIssuerFromIssuerType(
        WeIdAuthentication callerAuth,
        String issuerType,
        String targetIssuerWeId
    ) {
        ErrorCode innerCode = isSpecificTypeIssuerArgsValid(callerAuth, issuerType,
            targetIssuerWeId);
        if (innerCode != ErrorCode.SUCCESS) {
            return new ResponseData<>(false, innerCode);
        }
        try {
            String issuerAddress = WeIdUtils.convertWeIdToAddress(targetIssuerWeId);
            return authEngine.removeIssuer(
                issuerType,
                issuerAddress,
                callerAuth.getWeIdPrivateKey().getPrivateKey());
        } catch (Exception e) {
            logger.error("remove issuer from type failed.", e);
            return new ResponseData<>(false, ErrorCode.AUTHORITY_ISSUER_ERROR);
        }
    }

    /**
     * todo 判断issuer是否为指定机构里面的成员
     * Check if the given WeId is belonging to a specific issuer type.
     *
     * @param issuerType the issuer type
     * @param targetIssuerWeId the WeId
     * @return true if yes, false otherwise
     */
    public ResponseData<Boolean> isSpecificTypeIssuer(
        String issuerType,
        String targetIssuerWeId
    ) {
        ErrorCode errorCode = isIssuerTypeValid(issuerType);
        if (errorCode.getCode() != ErrorCode.SUCCESS.getCode()) {
            return new ResponseData<>(false, errorCode);
        }
        if (!weIdService.isWeIdExist(targetIssuerWeId).getResult()) {
            return new ResponseData<>(false, ErrorCode.WEID_DOES_NOT_EXIST);
        }
        try {
            String address = WeIdUtils.convertWeIdToAddress(targetIssuerWeId);
            return authEngine.isSpecificTypeIssuer(issuerType, address);
        } catch (Exception e) {
            logger.error("check issuer type failed.", e);
            return new ResponseData<>(false, ErrorCode.AUTHORITY_ISSUER_ERROR);
        }
    }

    /**
     * todo 获取指定索引范围内的issuer列表
     * Get all specific typed issuer in a list.
     *
     * @param issuerType the issuer type
     * @param index the start position index
     * @param num the number of issuers
     * @return the list
     */
    public ResponseData<List<String>> getAllSpecificTypeIssuerList(
        String issuerType,
        Integer index,
        Integer num
    ) {
        ErrorCode errorCode = isIssuerTypeValid(issuerType);
        if (errorCode.getCode() != ErrorCode.SUCCESS.getCode()) {
            return new ResponseData<>(null, errorCode);
        }
        errorCode = isStartEndPosValid(index, num);
        if (errorCode.getCode() != ErrorCode.SUCCESS.getCode()) {
            return new ResponseData<>(null, errorCode);
        }
        try {
            return authEngine.getSpecificTypeIssuerList(issuerType, index, num);
        } catch (Exception e) {
            logger.error("get all specific issuers failed.", e);
            return new ResponseData<>(null, ErrorCode.AUTHORITY_ISSUER_ERROR);
        }
    }

    private ErrorCode isStartEndPosValid(Integer index, Integer num) {
        if (index == null || index < 0 || num == null || num <= 0
            || num > WeIdConstant.MAX_AUTHORITY_ISSUER_LIST_SIZE) {
            return ErrorCode.ILLEGAL_INPUT;
        }
        return ErrorCode.SUCCESS;
    }

    private ErrorCode isSpecificTypeIssuerArgsValid(
        WeIdAuthentication callerAuth,
        String issuerType,
        String targetIssuerWeId
    ) {
        if (!WeIdUtils.isWeIdValid(targetIssuerWeId)) {
            return ErrorCode.WEID_INVALID;
        }
        if (!weIdService.isWeIdExist(targetIssuerWeId).getResult()) {
            return ErrorCode.WEID_DOES_NOT_EXIST;
        }
        ErrorCode errorCode = isCallerAuthValid(callerAuth);
        if (errorCode.getCode() == ErrorCode.SUCCESS.getCode()) {
            return isIssuerTypeValid(issuerType);
        }
        return errorCode;
    }

    private ErrorCode isCallerAuthValid(WeIdAuthentication callerAuth) {
        if (callerAuth == null) {
            return ErrorCode.ILLEGAL_INPUT;
        }
        if (!WeIdUtils.isWeIdValid(callerAuth.getWeId())) {
            return ErrorCode.WEID_INVALID;
        }
        if (!weIdService.isWeIdExist(callerAuth.getWeId()).getResult()) {
            return ErrorCode.WEID_DOES_NOT_EXIST;
        }
        if (callerAuth.getWeIdPrivateKey() == null
            || StringUtils.isEmpty(callerAuth.getWeIdPrivateKey().getPrivateKey())) {
            return ErrorCode.AUTHORITY_ISSUER_PRIVATE_KEY_ILLEGAL;
        }
        return ErrorCode.SUCCESS;
    }

    private ErrorCode isIssuerTypeValid(String issuerType) {
        if (StringUtils.isEmpty(issuerType)) {
            return ErrorCode.ILLEGAL_INPUT;
        }
        if (issuerType.length() > WeIdConstant.MAX_AUTHORITY_ISSUER_NAME_LENGTH) {
            return ErrorCode.SPECIFIC_ISSUER_TYPE_ILLEGAL;
        }
        return ErrorCode.SUCCESS;
    }

    private ErrorCode checkRegisterAuthorityIssuerArgs(
        RegisterAuthorityIssuerArgs args) {

        if (args == null) {
            return ErrorCode.ILLEGAL_INPUT;
        }
        ErrorCode errorCode = checkAuthorityIssuerArgsValidity(
            args.getAuthorityIssuer()
        );

        if (ErrorCode.SUCCESS.getCode() != errorCode.getCode()) {
            logger.error("register authority issuer format error!");
            return errorCode;
        }
        if (args.getWeIdPrivateKey() == null
            || StringUtils.isEmpty(args.getWeIdPrivateKey().getPrivateKey())) {
            return ErrorCode.AUTHORITY_ISSUER_PRIVATE_KEY_ILLEGAL;
        }
        // Need an extra check for the existence of WeIdentity DID on chain, in Register Case.
        ResponseData<Boolean> innerResponseData = weIdService
            .isWeIdExist(args.getAuthorityIssuer().getWeId());
        if (!innerResponseData.getResult()) {
            return ErrorCode.WEID_INVALID;
        }
        return ErrorCode.SUCCESS;
    }

    private ErrorCode checkRemoveAuthorityIssuerArgs(RemoveAuthorityIssuerArgs args) {

        if (args == null) {
            return ErrorCode.ILLEGAL_INPUT;
        }
        if (!WeIdUtils.isWeIdValid(args.getWeId())) {
            return ErrorCode.WEID_INVALID;
        }
        if (args.getWeIdPrivateKey() == null
            || StringUtils.isEmpty(args.getWeIdPrivateKey().getPrivateKey())) {
            return ErrorCode.AUTHORITY_ISSUER_PRIVATE_KEY_ILLEGAL;
        }
        return ErrorCode.SUCCESS;
    }

    private ErrorCode checkAuthorityIssuerArgsValidity(AuthorityIssuer args) {

        if (args == null) {
            return ErrorCode.ILLEGAL_INPUT;
        }
        if (!WeIdUtils.isWeIdValid(args.getWeId())) {
            return ErrorCode.WEID_INVALID;
        }
        String name = args.getName();
        if (!isValidAuthorityIssuerName(name)) {
            return ErrorCode.AUTHORITY_ISSUER_NAME_ILLEGAL;
        }
        // todo 问了官方的人, 说是 该发行人所有发行的 Credential 中 素数的乘积 Accumulator 的值 (有凭证撤销的时候, 这个值就会改变)
        String accValue = args.getAccValue();
        try {
            BigInteger accValueBigInteger = new BigInteger(accValue);
            logger.info(args.getWeId() + " accValue is: " + accValueBigInteger.longValue());
            if (accValueBigInteger.compareTo(BigInteger.ZERO) < 0) {
                return ErrorCode.AUTHORITY_ISSUER_ACCVALUE_ILLEAGAL;
            }
        } catch (Exception e) {
            logger.error("accValue is invalid.", e);
            return ErrorCode.AUTHORITY_ISSUER_ACCVALUE_ILLEAGAL;
        }

        return ErrorCode.SUCCESS;
    }

    private boolean isValidAuthorityIssuerName(String name) {
        return !StringUtils.isEmpty(name)
            && name.getBytes(StandardCharsets.UTF_8).length
            < WeIdConstant.MAX_AUTHORITY_ISSUER_NAME_LENGTH
            && !StringUtils.isWhitespace(name);
    }

    @Override
    public ResponseData<String> getWeIdByOrgId(String orgId) {
        if (!isValidAuthorityIssuerName(orgId)) {
            return new ResponseData<>(StringUtils.EMPTY, ErrorCode.AUTHORITY_ISSUER_NAME_ILLEGAL);
        }
        try {
            return authEngine.getWeIdFromOrgId(orgId);
        } catch (Exception e) {
            logger.error("Failed to get WeID, Error Message:{}", e);
            return new ResponseData<>(StringUtils.EMPTY, ErrorCode.AUTHORITY_ISSUER_ERROR);
        }
    }
}
