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

import java.util.HashMap;
import java.util.Map;

import com.webank.wedpr.selectivedisclosure.CredentialTemplateEntity;
import org.apache.commons.lang3.StringUtils;
import org.bcos.web3j.crypto.Sign.SignatureData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.webank.weid.constant.CredentialConstant;
import com.webank.weid.constant.ErrorCode;
import com.webank.weid.constant.JsonSchemaConstant;
import com.webank.weid.constant.WeIdConstant;
import com.webank.weid.protocol.base.Cpt;
import com.webank.weid.protocol.base.CptBaseInfo;
import com.webank.weid.protocol.base.WeIdAuthentication;
import com.webank.weid.protocol.base.WeIdPrivateKey;
import com.webank.weid.protocol.request.CptMapArgs;
import com.webank.weid.protocol.request.CptStringArgs;
import com.webank.weid.protocol.response.ResponseData;
import com.webank.weid.protocol.response.RsvSignature;
import com.webank.weid.rpc.CptService;
import com.webank.weid.suite.cache.CacheManager;
import com.webank.weid.suite.cache.CacheNode;
import com.webank.weid.util.DataToolUtils;
import com.webank.weid.util.WeIdUtils;

/**
 * todo 任何凭证的签发，都需要将数据转换成已经注册的CPT (Claim Protocol Type)格式规范，
 *      也就是所谓的“标准化格式化数据”。相关机构事先需要注册好CPT，
 *      在此之后，签发机构会根据CPT提供符合格式的数据，进而进行凭证的签发。
 *
 * todo 本接口提供了对CPT的注册、更新、查询等操作。
 * Service implementation for operation on CPT (Claim Protocol Type).
 *
 * @author lingfenghe
 */
public class CptServiceImpl extends AbstractService implements CptService {

    private static final Logger logger = LoggerFactory.getLogger(CptServiceImpl.class);
    //获取CPT缓存节点
    private static CacheNode<ResponseData<Cpt>> cptCahceNode =
        CacheManager.registerCacheNode("SYS_CPT", 1000 * 3600 * 24L);

    /**
     * todo 传入WeIdentity DID，JsonSchema(String类型) , cptId和其对应的私钥，链上注册指定cptId的CPT，返回CPT编号和版本
     *
     * todo 使用代码示例：
     *
     *      CptService cptService = new CptServiceImpl();
     *
     *      String jsonSchema = "{\"properties\" : {\"id\": {\"type\": \"string\",\"description\": \"the id of certificate owner\"}, \"name\": {\"type\": \"string\",\"description\": \"the name of certificate owner\"},\"gender\": {\"enum\": [\"F\", \"M\"],\"type\": \"string\",\"description\": \"the gender of certificate owner\"}, \"age\": {\"type\": \"number\", \"description\": \"the age of certificate owner\"}},\"required\": [\"id\", \"name\", \"age\"]}";
     *
     *      WeIdPrivateKey weIdPrivateKey = new WeIdPrivateKey();
     *      weIdPrivateKey.setPrivateKey("60866441986950167911324536025850958917764441489874006048340539971987791929772");
     *
     *      WeIdAuthentication weIdAuthentication = new WeIdAuthentication();
     *      weIdAuthentication.setWeId("did:weid:101:0x39e5e6f663ef77409144014ceb063713b65600e7");
     *      weIdAuthentication.setWeIdPrivateKey(weIdPrivateKey);
     *
     *      CptStringArgs cptStringArgs = new CptStringArgs();
     *      cptStringArgs.setCptJsonSchema(jsonSchema);
     *      cptStringArgs.setWeIdAuthentication(weIdAuthentication);
     *
     *      ResponseData<CptBaseInfo> response = cptService.registerCpt(cptStringArgs, 103);
     *
     *
     * todo jsonschema 例如:
     *
     *   {
     *       "properties":{
     *           "id":{
     *               "type":"string",
     *               "description":"the id of certificate owner"
     *           },
     *           "name":{
     *               "type":"string",
     *               "description":"the name of certificate owner"
     *           },
     *           "gender":{
     *               "enum":[
     *                   "F",
     *                   "M"
     *               ],
     *               "type":"string",
     *               "description":"the gender of certificate owner"
     *           },
     *           "age":{
     *               "type":"number",
     *               "description":"the age of certificate owner"
     *           }
     *       },
     *       "required":[
     *           "id",
     *           "name",
     *           "age"
     *       ]
     *   }
     *
     *
     * todo 注册一个 CPT 模板到 chain 上
     * 将具有预设CPT ID的新CPT注册到区块链。
     * Register a new CPT with a pre-set CPT ID, to the blockchain.
     *
     * @param args the args
     * @param cptId the CPT ID
     * @return response data
     */
    public ResponseData<CptBaseInfo> registerCpt(CptStringArgs args, Integer cptId) {
        if (args == null || cptId == null || cptId <= 0) {
            logger.error(
                "[registerCpt1] input argument is illegal");
            return new ResponseData<>(null, ErrorCode.ILLEGAL_INPUT);
        }
        try {
            CptMapArgs cptMapArgs = new CptMapArgs();
            cptMapArgs.setWeIdAuthentication(args.getWeIdAuthentication());
            Map<String, Object> cptJsonSchemaMap =
                DataToolUtils.deserialize(args.getCptJsonSchema(), HashMap.class);
            cptMapArgs.setCptJsonSchema(cptJsonSchemaMap);
            return this.registerCpt(cptMapArgs, cptId);
        } catch (Exception e) {
            logger.error("[registerCpt1] register cpt failed due to unknown error. ", e);
            return new ResponseData<>(null, ErrorCode.UNKNOW_ERROR);
        }
    }


    /**
     * todo 传入WeIdentity DID，JsonSchema(String类型) 和其对应的私钥，链上注册CPT，返回CPT编号和版本
     * This is used to register a new CPT to the blockchain.
     *
     * @param args the args
     * @return the response data
     */
    public ResponseData<CptBaseInfo> registerCpt(CptStringArgs args) {

        try {
            if (args == null) {
                logger.error(
                    "[registerCpt1]input CptStringArgs is null");
                return new ResponseData<>(null, ErrorCode.ILLEGAL_INPUT);
            }

            // 本次入参只有三部分, auth、jsonSchema、type
            CptMapArgs cptMapArgs = new CptMapArgs();
            cptMapArgs.setWeIdAuthentication(args.getWeIdAuthentication());
            Map<String, Object> cptJsonSchemaMap =
                DataToolUtils.deserialize(args.getCptJsonSchema(), HashMap.class);
            cptMapArgs.setCptJsonSchema(cptJsonSchemaMap);
            return this.registerCpt(cptMapArgs);
        } catch (Exception e) {
            logger.error("[registerCpt1] register cpt failed due to unknown error. ", e);
            return new ResponseData<>(null, ErrorCode.UNKNOW_ERROR);
        }
    }

    /**
     * todo 传入WeIdentity DID，JsonSchema(Map类型), cptId 和其对应的私钥，链上注册指定cptId的CPT，返回CPT编号和版本。
     * Register a new CPT with a pre-set CPT ID, to the blockchain.
     *
     * @param args the args
     * @param cptId the CPT ID
     * @return response data
     */
    public ResponseData<CptBaseInfo> registerCpt(CptMapArgs args, Integer cptId) {
        if (args == null || cptId == null || cptId <= 0) {
            logger.error("[registerCpt] input argument is illegal");
            return new ResponseData<>(null, ErrorCode.ILLEGAL_INPUT);
        }
        try {
            ErrorCode errorCode =
                this.validateCptArgs(
                    args.getWeIdAuthentication(),
                    args.getCptJsonSchema()
                );
            if (errorCode.getCode() != ErrorCode.SUCCESS.getCode()) {
                return new ResponseData<>(null, errorCode);
            }

            String weId = args.getWeIdAuthentication().getWeId();
            WeIdPrivateKey weIdPrivateKey = args.getWeIdAuthentication().getWeIdPrivateKey();
            String cptJsonSchemaNew = this.cptSchemaToString(args);
            RsvSignature rsvSignature = sign(
                weId,
                cptJsonSchemaNew,
                weIdPrivateKey);
            String address = WeIdUtils.convertWeIdToAddress(weId);
            return cptServiceEngine.registerCpt(cptId, address, cptJsonSchemaNew, rsvSignature,
                weIdPrivateKey.getPrivateKey());
        } catch (Exception e) {
            logger.error("[registerCpt] register cpt failed due to unknown error. ", e);
            return new ResponseData<>(null, ErrorCode.UNKNOW_ERROR);
        }
    }

    /**
     * todo 传入WeIdentity DID，JsonSchema(Map类型) 和其对应的私钥，链上注册CPT，返回CPT编号和版本
     * This is used to register a new CPT to the blockchain.
     *
     * @param args the args
     * @return the response data
     */
    public ResponseData<CptBaseInfo> registerCpt(CptMapArgs args) {

        try {
            if (args == null) {
                logger.error("[registerCpt]input CptMapArgs is null");
                return new ResponseData<>(null, ErrorCode.ILLEGAL_INPUT);
            }
            ErrorCode validateResult =
                this.validateCptArgs(
                    args.getWeIdAuthentication(),
                    args.getCptJsonSchema()
                );

            if (validateResult.getCode() != ErrorCode.SUCCESS.getCode()) {
                return new ResponseData<>(null, validateResult);
            }

            String weId = args.getWeIdAuthentication().getWeId();
            WeIdPrivateKey weIdPrivateKey = args.getWeIdAuthentication().getWeIdPrivateKey();
            String cptJsonSchemaNew = this.cptSchemaToString(args);
            RsvSignature rsvSignature = sign(
                weId,
                cptJsonSchemaNew,
                weIdPrivateKey);
            String address = WeIdUtils.convertWeIdToAddress(weId);
            return cptServiceEngine.registerCpt(address, cptJsonSchemaNew, rsvSignature,
                weIdPrivateKey.getPrivateKey());
        } catch (Exception e) {
            logger.error("[registerCpt] register cpt failed due to unknown error. ", e);
            return new ResponseData<>(null, ErrorCode.UNKNOW_ERROR);
        }
    }

    /**
     * todo 根据CPT编号查询CPT信息
     * this is used to query cpt with the latest version which has been registered.
     *
     * @param cptId the cpt id
     * @return the response data
     */
    public ResponseData<Cpt> queryCpt(Integer cptId) {

        try {
            if (cptId == null || cptId < 0) {
                return new ResponseData<>(null, ErrorCode.CPT_ID_ILLEGAL);
            }
            String cptIdStr = String.valueOf(cptId);
            ResponseData<Cpt> result = cptCahceNode.get(cptIdStr);
            if (result == null) {
                result = cptServiceEngine.queryCpt(cptId);
                if (result.getErrorCode().intValue() == ErrorCode.SUCCESS.getCode()) {
                    cptCahceNode.put(cptIdStr, result);
                }
            }
            return result;
        } catch (Exception e) {
            logger.error("[updateCpt] query cpt failed due to unknown error. ", e);
            return new ResponseData<>(null, ErrorCode.UNKNOW_ERROR);
        }
    }

    /**
     * todo  传入cptId，JsonSchema(String类型)，WeIdentity DID，WeIdentity DID所属私钥，进行更新CPT信息，更新成功版本自动+1
     * This is used to update a CPT data which has been register.
     *
     * @param args the args
     * @return the response data
     */
    public ResponseData<CptBaseInfo> updateCpt(CptStringArgs args, Integer cptId) {

        try {
            if (args == null) {
                logger.error("[updateCpt1]input UpdateCptArgs is null");
                return new ResponseData<>(null, ErrorCode.ILLEGAL_INPUT);
            }

            CptMapArgs cptMapArgs = new CptMapArgs();
            cptMapArgs.setWeIdAuthentication(args.getWeIdAuthentication());
            cptMapArgs.setCptJsonSchema(
                DataToolUtils.deserialize(args.getCptJsonSchema(), HashMap.class));
            return this.updateCpt(cptMapArgs, cptId);
        } catch (Exception e) {
            logger.error("[updateCpt1] update cpt failed due to unkown error. ", e);
            return new ResponseData<>(null, ErrorCode.UNKNOW_ERROR);
        }
    }

    /**
     * todo 传入cptId，JsonSchema(Map类型)，WeIdentity DID，WeIdentity DID所属私钥，进行更新CPT信息，更新成功版本自动+1
     * This is used to update a CPT data which has been register.
     *
     * @param args the args
     * @return the response data
     */
    public ResponseData<CptBaseInfo> updateCpt(CptMapArgs args, Integer cptId) {

        try {
            if (args == null) {
                logger.error("[updateCpt]input UpdateCptArgs is null");
                return new ResponseData<>(null, ErrorCode.ILLEGAL_INPUT);
            }
            if (cptId == null || cptId.intValue() < 0) {
                logger.error("[updateCpt]input cptId illegal");
                return new ResponseData<>(null, ErrorCode.CPT_ID_ILLEGAL);
            }
            ErrorCode errorCode =
                this.validateCptArgs(
                    args.getWeIdAuthentication(),
                    args.getCptJsonSchema()
                );

            if (errorCode.getCode() != ErrorCode.SUCCESS.getCode()) {
                return new ResponseData<>(null, errorCode);
            }

            String weId = args.getWeIdAuthentication().getWeId();
            WeIdPrivateKey weIdPrivateKey = args.getWeIdAuthentication().getWeIdPrivateKey();
            String cptJsonSchemaNew = this.cptSchemaToString(args);
            RsvSignature rsvSignature = sign(
                weId,
                cptJsonSchemaNew,
                weIdPrivateKey);
            String address = WeIdUtils.convertWeIdToAddress(weId);
            ResponseData<CptBaseInfo> result = cptServiceEngine.updateCpt(
                cptId,
                address,
                cptJsonSchemaNew,
                rsvSignature,
                weIdPrivateKey.getPrivateKey());
            if (result.getErrorCode().intValue() == ErrorCode.SUCCESS.getCode()) {
                cptCahceNode.remove(String.valueOf(cptId));
            }
            return result;
        } catch (Exception e) {
            logger.error("[updateCpt] update cpt failed due to unkown error. ", e);
            return new ResponseData<>(null, ErrorCode.UNKNOW_ERROR);
        }
    }


    private RsvSignature sign(
        String cptPublisher,
        String jsonSchema,
        WeIdPrivateKey cptPublisherPrivateKey) {

        StringBuilder sb = new StringBuilder();
        sb.append(cptPublisher);
        sb.append(WeIdConstant.PIPELINE);
        sb.append(jsonSchema);
        SignatureData signatureData =
            DataToolUtils.signMessage(sb.toString(), cptPublisherPrivateKey.getPrivateKey());
        return DataToolUtils.convertSignatureDataToRsv(signatureData);
    }

    private ErrorCode validateCptArgs(
        WeIdAuthentication weIdAuthentication,
        Map<String, Object> cptJsonSchemaMap) throws Exception {

        if (weIdAuthentication == null) {
            logger.error("Input cpt weIdAuthentication is invalid.");
            return ErrorCode.WEID_AUTHORITY_INVALID;
        }

        String weId = weIdAuthentication.getWeId();
        if (!WeIdUtils.isWeIdValid(weId)) {
            logger.error("Input cpt publisher : {} is invalid.", weId);
            return ErrorCode.WEID_INVALID;
        }

        ErrorCode errorCode = validateCptJsonSchemaMap(cptJsonSchemaMap);
        if (errorCode.getCode() != ErrorCode.SUCCESS.getCode()) {
            return errorCode;
        }
        String cptJsonSchema = DataToolUtils.serialize(cptJsonSchemaMap);
        if (!DataToolUtils.isCptJsonSchemaValid(cptJsonSchema)) {
            logger.error("Input cpt json schema : {} is invalid.", cptJsonSchemaMap);
            return ErrorCode.CPT_JSON_SCHEMA_INVALID;
        }
        WeIdPrivateKey weIdPrivateKey = weIdAuthentication.getWeIdPrivateKey();
        if (weIdPrivateKey == null
            || StringUtils.isEmpty(weIdPrivateKey.getPrivateKey())) {
            logger.error(
                "Input cpt publisher private key : {} is in valid.",
                weIdPrivateKey
            );
            return ErrorCode.WEID_PRIVATEKEY_INVALID;
        }

        if (!WeIdUtils.validatePrivateKeyWeIdMatches(weIdPrivateKey, weId)) {
            return ErrorCode.WEID_PRIVATEKEY_DOES_NOT_MATCH;
        }
        return ErrorCode.SUCCESS;
    }

    private ErrorCode validateCptJsonSchemaMap(
        Map<String, Object> cptJsonSchemaMap) throws Exception {
        if (cptJsonSchemaMap == null || cptJsonSchemaMap.isEmpty()) {
            logger.error("Input cpt json schema is invalid.");
            return ErrorCode.CPT_JSON_SCHEMA_INVALID;
        }
        //String cptJsonSchema = JsonUtil.objToJsonStr(cptJsonSchemaMap);
        String cptJsonSchema = DataToolUtils.serialize(cptJsonSchemaMap);
        if (!DataToolUtils.isCptJsonSchemaValid(cptJsonSchema)) {
            logger.error("Input cpt json schema : {} is invalid.", cptJsonSchemaMap);
            return ErrorCode.CPT_JSON_SCHEMA_INVALID;
        }
        return ErrorCode.SUCCESS;
    }

    /**
     * create new cpt json schema.
     *
     * @return String
     */
    private String cptSchemaToString(CptMapArgs args) throws Exception {

        Map<String, Object> cptJsonSchema = args.getCptJsonSchema();
        Map<String, Object> cptJsonSchemaNew = new HashMap<String, Object>();
        cptJsonSchemaNew.put(JsonSchemaConstant.SCHEMA_KEY, JsonSchemaConstant.SCHEMA_VALUE);
        cptJsonSchemaNew.put(JsonSchemaConstant.TYPE_KEY, JsonSchemaConstant.DATA_TYPE_OBJECT);
        cptJsonSchemaNew.putAll(cptJsonSchema);
        String cptType = args.getCptType().getName();
        cptJsonSchemaNew.put(CredentialConstant.CPT_TYPE_KEY, cptType);
        return DataToolUtils.serialize(cptJsonSchemaNew);
    }

    // todo 根据 CPT Id 去chain 上查回, Credential 需要用的 Claim jsonSchame / CredentialTemplate的 Pubkey 和 Proof
    /* (non-Javadoc)
     * @see com.webank.weid.rpc.CptService#queryCredentialTemplate(java.lang.Integer)
     */
    @Override
    public ResponseData<CredentialTemplateEntity> queryCredentialTemplate(Integer cptId) {

        // todo 根据 CPT Id 去chain 上查回, Credential 需要用的 Claim jsonSchame / CredentialTemplate的 Pubkey 和 Proof
        return cptServiceEngine.queryCredentialTemplate(cptId);
    }
}
