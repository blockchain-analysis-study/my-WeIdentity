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

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import com.webank.wedpr.common.Utils;
import com.webank.wedpr.selectivedisclosure.CredentialTemplateEntity;
import com.webank.wedpr.selectivedisclosure.PredicateType;
import com.webank.wedpr.selectivedisclosure.UserClient;
import com.webank.wedpr.selectivedisclosure.UserResult;
import com.webank.wedpr.selectivedisclosure.VerifierClient;
import com.webank.wedpr.selectivedisclosure.VerifierResult;
import com.webank.wedpr.selectivedisclosure.proto.Predicate;
import com.webank.wedpr.selectivedisclosure.proto.VerificationRule;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.bcos.web3j.abi.datatypes.Address;
import org.bcos.web3j.crypto.ECKeyPair;
import org.bcos.web3j.crypto.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.webank.weid.constant.CredentialConstant;
import com.webank.weid.constant.CredentialConstant.CredentialProofType;
import com.webank.weid.constant.CredentialFieldDisclosureValue;
import com.webank.weid.constant.CredentialType;
import com.webank.weid.constant.DataDriverConstant;
import com.webank.weid.constant.ErrorCode;
import com.webank.weid.constant.ParamKeyConstant;
import com.webank.weid.constant.WeIdConstant;
import com.webank.weid.exception.DataTypeCastException;
import com.webank.weid.exception.WeIdBaseException;
import com.webank.weid.protocol.base.Challenge;
import com.webank.weid.protocol.base.ClaimPolicy;
import com.webank.weid.protocol.base.Cpt;
import com.webank.weid.protocol.base.CredentialPojo;
import com.webank.weid.protocol.base.PresentationE;
import com.webank.weid.protocol.base.PresentationPolicyE;
import com.webank.weid.protocol.base.WeIdAuthentication;
import com.webank.weid.protocol.base.WeIdDocument;
import com.webank.weid.protocol.base.WeIdPublicKey;
import com.webank.weid.protocol.cpt.Cpt101;
import com.webank.weid.protocol.cpt.Cpt111;
import com.webank.weid.protocol.request.CreateCredentialPojoArgs;
import com.webank.weid.protocol.response.ResponseData;
import com.webank.weid.rpc.CptService;
import com.webank.weid.rpc.CredentialPojoService;
import com.webank.weid.rpc.WeIdService;
import com.webank.weid.suite.api.persistence.Persistence;
import com.webank.weid.suite.api.transportation.inf.PdfTransportation;
import com.webank.weid.suite.persistence.sql.driver.MysqlDriver;
import com.webank.weid.suite.transportation.pdf.impl.PdfTransportationImpl;
import com.webank.weid.suite.transportation.pdf.protocol.PdfAttributeInfo;
import com.webank.weid.util.CredentialPojoUtils;
import com.webank.weid.util.CredentialUtils;
import com.webank.weid.util.DataToolUtils;
import com.webank.weid.util.DateUtils;
import com.webank.weid.util.JsonUtil;
import com.webank.weid.util.TimestampUtils;
import com.webank.weid.util.WeIdUtils;


/**
 *
 * TODO 凭证签发相关功能的核心接口。 (而 CredentialServiceImpl 后续作废)
 *
 * TODO 新版都用这个 生成 Credential
 *
 * todo 本接口提供凭证的签发和验证操作、Verifiable Presentation的签发和验证操作。
 *
 * Service implementations for operations on CredentialPojo.
 *
 * @author tonychen 2019年4月17日
 */
public class CredentialPojoServiceImpl implements CredentialPojoService {

    private static final Logger logger = LoggerFactory.getLogger(CredentialPojoServiceImpl.class);
    private static final String NOT_DISCLOSED =
        CredentialFieldDisclosureValue.NOT_DISCLOSED.getStatus().toString();
    private static final String DISCLOSED =
        CredentialFieldDisclosureValue.DISCLOSED.getStatus().toString();
    private static final String EXISTED =
        CredentialFieldDisclosureValue.EXISTED.getStatus().toString();
    private static WeIdService weIdService;
    private static CptService cptService;
    private static Persistence dataDriver;
    private static PdfTransportation pdfTransportation;

    private static Persistence getDataDriver() {
        if (dataDriver == null) {
            dataDriver = new MysqlDriver();
        }
        return dataDriver;
    }

    private static WeIdService getWeIdService() {
        if (weIdService == null) {
            weIdService = new WeIdServiceImpl();
        }
        return weIdService;
    }

    private static CptService getCptService() {
        if (cptService == null) {
            cptService = new CptServiceImpl();
        }
        return cptService;
    }

    private static PdfTransportation getPdfTransportation() {
        if (pdfTransportation == null) {
            pdfTransportation = new PdfTransportationImpl();
        }
        return pdfTransportation;
    }

    /**
     * Salt generator. Automatically fillin the map structure in a recursive manner.
     *
     * @param map the passed map (claim, salt or alike)
     * @param fixed fixed value if required to use
     */
    public static void generateSalt(Map<String, Object> map, Object fixed) {
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            Object value = entry.getValue();
            if (value instanceof Map) {
                generateSalt((HashMap) value, fixed);
            } else if (value instanceof List) {
                boolean isMapOrList = generateSaltFromList((ArrayList<Object>) value, fixed);
                if (!isMapOrList) {
                    if (fixed == null) {
                        addSalt(entry);
                    } else {
                        entry.setValue(fixed);
                    }
                }
            } else {
                if (fixed == null) {
                    // 添加 随机 salt
                    addSalt(entry);
                } else {
                    // 添加 指定 salt
                    entry.setValue(fixed);
                }
            }
        }
    }

    // TODO 添加 随机 salt 到 Entry 中
    private static void addSalt(Map.Entry<String, Object> entry) {
        String salt = DataToolUtils.getRandomSalt();
        entry.setValue(salt);
    }

    // 给 [] 类型的 field 生成对应的 salt
    private static boolean generateSaltFromList(List<Object> objList, Object fixed) {
        List<Object> list = (List<Object>) objList;
        for (Object obj : list) {
            if (obj instanceof Map) {
                generateSalt((HashMap) obj, fixed);
            } else if (obj instanceof List) {
                boolean result = generateSaltFromList((ArrayList<Object>) obj, fixed);
                if (!result) {
                    return result;
                }
            } else {
                return false;
            }
        }
        return true;
    }

    /**
     * todo 校验claim、salt和disclosureMap的格式是否一致.
     */
    private static boolean validCredentialMapArgs(Map<String, Object> claim,
        Map<String, Object> salt, Map<String, Object> disclosureMap) {

        //检查是否为空
        if (claim == null || salt == null || disclosureMap == null) {
            return false;
        }

        //检查每个map里的key个数是否相同
        if (!claim.keySet().equals(salt.keySet())) {
            return false;
        }

        //检查key值是否一致
        for (Map.Entry<String, Object> entry : disclosureMap.entrySet()) {
            String k = entry.getKey();
            Object v = entry.getValue();
            //如果disclosureMap中的key在claim中没有则返回false
            if (!claim.containsKey(k)) {
                return false;
            }
            Object saltV = salt.get(k);
            Object claimV = claim.get(k);
            if (v instanceof Map) {
                //递归检查
                if (!validCredentialMapArgs((HashMap) claimV, (HashMap) saltV, (HashMap) v)) {
                    return false;
                }
            } else if (v instanceof List) {
                if (!validCredentialListArgs(
                    (ArrayList<Object>) claimV,
                    (ArrayList<Object>) saltV,
                    (ArrayList<Object>) v
                )) {
                    return false;
                }
            }
        }
        return true;
    }

    private static boolean validCredentialListArgs(
        List<Object> claimList,
        List<Object> saltList,
        List<Object> disclosureList) {
        //检查是否为空
        if (claimList == null || saltList == null || disclosureList == null) {
            return false;
        }
        if (claimList.size() != saltList.size()) {
            return false;
        }
        for (int i = 0; i < disclosureList.size(); i++) {
            Object disclosureObj = disclosureList.get(i);
            Object claimObj = claimList.get(i);
            Object saltObj = saltList.get(i);
            if (disclosureObj instanceof Map) {
                boolean result =
                    validCredentialListArgs(
                        claimList,
                        saltList,
                        (HashMap) disclosureObj
                    );
                if (!result) {
                    return result;
                }
            } else if (disclosureObj instanceof List) {
                boolean result =
                    validCredentialListArgs(
                        (ArrayList<Object>) claimObj,
                        (ArrayList<Object>) saltObj,
                        (ArrayList<Object>) disclosureObj
                    );
                if (!result) {
                    return result;
                }
            }
        }
        return true;
    }

    private static boolean validCredentialListArgs(
        List<Object> claimList,
        List<Object> saltList,
        Map<String, Object> disclosure
    ) {

        if (claimList == null || saltList == null || saltList.size() != claimList.size()) {
            return false;
        }

        for (int i = 0; i < claimList.size(); i++) {
            Object claim = claimList.get(i);
            Object salt = saltList.get(i);
            boolean result = validCredentialMapArgs((HashMap) claim, (HashMap) salt, disclosure);
            if (!result) {
                return result;
            }
        }
        return true;
    }

    // 向policy中补充缺失的key
    private static void addKeyToPolicy(
        Map<String, Object> disclosureMap,    // 选择性披露 字段的 key => value  需要回填信息的
        Map<String, Object> claimMap          // 需要用于对比 原始Claim
    ) {

        // todo 遍历当前 Claim
        for (Map.Entry<String, Object> entry : claimMap.entrySet()) {
            String claimK = entry.getKey();
            Object claimV = entry.getValue();

            // todo 处理是 Map 的Value
            if (claimV instanceof Map) {
                HashMap claimHashMap = (HashMap) claimV;

                // 如果 不具备选择性披露, 则需要在 选择性披露的 Map 中加入 fieldName => {} 的 k-v
                if (!disclosureMap.containsKey(claimK)) {
                    disclosureMap.put(claimK, new HashMap());
                }
                HashMap disclosureHashMap = (HashMap) disclosureMap.get(claimK);

                addKeyToPolicy(disclosureHashMap, claimHashMap); // 递归处理 因为 Claim 中可能 嵌套多层 json 哦
            }
            // 处理是 List 的Value
            else if (claimV instanceof List) {
                ArrayList claimList = (ArrayList) claimV;
                //判断claimList中是否包含Map结构，还是单一结构
                boolean isSampleList = isSampleListForClaim(claimList);
                if (isSampleList) {
                    // 如果 不具备选择性披露, 则需要在 选择性披露的 Map 中加入 fieldName => 0 的 k-v
                    if (!disclosureMap.containsKey(claimK)) {
                        disclosureMap.put(claimK, Integer.parseInt(NOT_DISCLOSED));
                    }
                } else {

                    // 如果 不具备选择性披露, 则需要在 选择性披露的 Map 中加入 fieldName => [] 的 k-v
                    if (!disclosureMap.containsKey(claimK)) {
                        disclosureMap.put(claimK, new ArrayList());
                    }


                    ArrayList disclosureList = (ArrayList) disclosureMap.get(claimK);
                    addKeyToPolicyList(disclosureList, claimList);
                }
            }
            // 处理 正常 单值的 Value
            else {
                // todo 如果不存在 选择性披露的Map 中, 需要放入 filedName => 0 这样的 k-v
                if (!disclosureMap.containsKey(claimK)) {
                    disclosureMap.put(claimK, Integer.parseInt(NOT_DISCLOSED));
                }
            }
        }
    }

    private static void addKeyToPolicyList(
        ArrayList disclosureList,
        ArrayList claimList
    ) {
        for (int i = 0; i < claimList.size(); i++) {
            Object claimObj = claimList.get(i);
            if (claimObj instanceof Map) {
                Object disclosureObj = disclosureList.size() == 0 ? null : disclosureList.get(0);
                if (disclosureObj == null) {
                    disclosureList.add(new HashMap());
                }
                HashMap disclosureHashMap = (HashMap) disclosureList.get(0);
                addKeyToPolicy(disclosureHashMap, (HashMap) claimObj);
                break;
            } else if (claimObj instanceof List) {
                Object disclosureObj = disclosureList.get(i);
                if (disclosureObj == null) {
                    disclosureList.add(new ArrayList());
                }
                ArrayList disclosureArrayList = (ArrayList) disclosureList.get(i);
                addKeyToPolicyList(disclosureArrayList, (ArrayList) claimObj);
            }
        }
    }

    private static boolean isSampleListForClaim(ArrayList claimList) {
        if (CollectionUtils.isEmpty(claimList)) {
            return true;
        }
        Object claimObj = claimList.get(0);
        if (claimObj instanceof Map) {
            return false;
        }
        if (claimObj instanceof List) {
            return isSampleListForClaim((ArrayList) claimObj);
        }
        return true;
    }


    // todo  对非选择性披露的 Claim 字段的值 做加salt算Hash处理
    private static void addSelectSalt(
        Map<String, Object> disclosureMap,
        Map<String, Object> saltMap,
        Map<String, Object> claim,
        boolean isZkp
    ) {

        // todo  遍历当前 选择性披露的 Map
        for (Map.Entry<String, Object> entry : disclosureMap.entrySet()) {

            String disclosureKey = entry.getKey();  // 选择性披露的 key
            Object value = entry.getValue();        // 选择性披露的 value todo 这个如果不具备 选择性披露的话一般是 空值 `{} []` 或者 0值

            Object saltV = saltMap.get(disclosureKey);  // 根据 key 获取 对应 key 上的 salt
            Object claimV = claim.get(disclosureKey);   // 根据 key 获取Claim 中 对应 key 上的原始 value

            // todo 选择性披露的value 情况一, 永远不存在
            if (value == null) {
                throw new WeIdBaseException(ErrorCode.CREDENTIAL_POLICY_DISCLOSUREVALUE_ILLEGAL);
            }

            // todo 选择性披露的value 情况二, 类型 map
            else if ((value instanceof Map) && (claimV instanceof Map)) {
                // 需要 一层层出力
                addSelectSalt((HashMap) value, (HashMap) saltV, (HashMap) claimV, isZkp); // 递归

            }

            // todo 选择性披露的value 情况三, 类型 list
            else if (value instanceof List) {
                addSaltForList(
                    (ArrayList<Object>) value,
                    (ArrayList<Object>) saltV,
                    (ArrayList<Object>) claimV,
                    isZkp
                );
            }

            // todo 选择性披露的value 情况三, 类型 单值
            else {
                // TODO 对 非披露的值做加salt算Hash 处理
                addHashToClaim(saltMap, claim, disclosureKey, value, saltV, claimV, isZkp);
            }
        }
    }

    // 给 Claim 中非披露的值 做加salt 算Hash 处理
    private static void addHashToClaim(
        Map<String, Object> saltMap,    // 用于清空 salt
        Map<String, Object> claim,      // 用来 回填 算了Hash 之后的Claim
        String disclosureKey,           // 当前正在处理的 Claim 的某个字段
        Object value,                   // 当前正在处理的 Claim 的某个字段 在 disclosure中的 value
        Object saltV,                   // 当前正在处理的 Claim 的某个字段 在 saltMap 中对应的 salt值
        Object claimV,                  // 当前正在处理的 Claim 的某个字段 在ClaimMap 中对应的 原始值
        boolean isZkp                   // 是否启用 零知识证明 标识位
    ) {

        // 如果是 用 zkp 形式
        if (isZkp) {
            // todo 这个 处理的对么 ?? 感觉很怪的处理啊 ??
            if ((value instanceof Map) || !(((Integer) value).equals(Integer.parseInt(DISCLOSED))
                && claim.containsKey(disclosureKey))) {
                String hash =
                    CredentialPojoUtils.getFieldSaltHash(
                        String.valueOf(claimV),
                        String.valueOf(saltV)
                    );
                claim.put(disclosureKey, hash);
            }
        }
        // 如果 不是 zkp 形式出力
        else {

            // todo 如果 value 是 【非选择性披露】
            if (((Integer) value).equals(Integer.parseInt(NOT_DISCLOSED))
                && claim.containsKey(disclosureKey)) {
                // todo 覆盖掉 salMap 中对应的 saltValue, 也就是说 将 salt 清空掉
                // todo 设置为 "0"值
                saltMap.put(disclosureKey, NOT_DISCLOSED);

                // TODO 计算 非披露的值的Hash
                String hash =
                    CredentialPojoUtils.getFieldSaltHash(
                        String.valueOf(claimV),
                        String.valueOf(saltV)
                    );

                // 将 非披露的值, 放回 Claim 中
                claim.put(disclosureKey, hash);
            }
        }
    }

    private static void addSaltForList(
        List<Object> disclosures,
        List<Object> salt,
        List<Object> claim,
        boolean isZkp) {
        for (int i = 0; claim != null && i < disclosures.size(); i++) {
            Object disclosureObj = disclosures.get(i);
            Object claimObj = claim.get(i);
            Object saltObj = salt.get(i);
            if (disclosureObj instanceof Map) {
                addSaltForList((HashMap) disclosureObj, salt, claim, isZkp);
            } else if (disclosureObj instanceof List) {
                addSaltForList(
                    (ArrayList<Object>) disclosureObj,
                    (ArrayList<Object>) saltObj,
                    (ArrayList<Object>) claimObj,
                    isZkp
                );
            }
        }
    }

    private static void addSaltForList(
        Map<String, Object> disclosures,
        List<Object> salt,
        List<Object> claim,
        boolean isZkp
    ) {
        for (int i = 0; claim != null && i < claim.size(); i++) {
            Object claimObj = claim.get(i);
            Object saltObj = salt.get(i);
            addSelectSalt(disclosures, (HashMap) saltObj, (HashMap) claimObj, isZkp);
        }
    }

    private static ErrorCode verifyContent(
        CredentialPojo credential,
        String publicKey,
        boolean offLine
    ) {
        ErrorCode errorCode;
        try {
            errorCode = verifyContentInner(credential, publicKey, offLine);
        } catch (WeIdBaseException ex) {
            logger.error("[verifyContent] verify credential has exception.", ex);
            return ex.getErrorCode();
        }
        // System CPT business related check
        if (errorCode == ErrorCode.SUCCESS
            && CredentialPojoUtils.isSystemCptId(credential.getCptId())) {
            errorCode = verifySystemCptClaimInner(credential);
        }
        return errorCode;
    }

    private static ErrorCode verifySystemCptClaimInner(CredentialPojo credential) {
        if (credential.getCptId().intValue() == CredentialConstant.EMBEDDED_TIMESTAMP_CPT) {
            return verifyTimestampClaim(credential);
        }
        if (credential.getCptId().intValue() == CredentialConstant.AUTHORIZATION_CPT) {
            return verifyAuthClaim(credential);
        }
        return ErrorCode.SUCCESS;
    }

    private static ErrorCode verifyAuthClaim(CredentialPojo credential) {
        Cpt101 authInfo;
        try {
            authInfo = DataToolUtils.mapToObj(credential.getClaim(), Cpt101.class);
        } catch (Exception e) {
            logger.error("Failed to deserialize authorization information.");
            return ErrorCode.CREDENTIAL_CLAIM_DATA_ILLEGAL;
        }
        ErrorCode errorCode = verifyAuthInfo(authInfo);
        if (errorCode != ErrorCode.SUCCESS) {
            return errorCode;
        }
        // Extra check 1: cannot authorize other WeID's resources
        String issuerWeId = credential.getIssuer();
        if (!issuerWeId.equalsIgnoreCase(authInfo.getFromWeId())) {
            return ErrorCode.AUTHORIZATION_CANNOT_AUTHORIZE_OTHER_WEID_RESOURCE;
        }
        // TODO Extra check 2: check service url endpoint exposed or not?
        // Need getWeIdDocument() check
        return ErrorCode.SUCCESS;
    }

    private static ErrorCode verifyTimestampClaim(CredentialPojo credential) {
        Map<String, Object> claim = credential.getClaim();
        if (((String) claim.get("timestampAuthority"))
            .contains(TimestampUtils.WESIGN_AUTHORITY_NAME)) {
            String hashValue = (String) claim.get("claimHash");
            String authoritySignature = (String) claim.get("authoritySignature");
            Long timestamp = (long) claim.get("timestamp");
            ResponseData<Boolean> resp =
                TimestampUtils.verifyWeSignTimestamp(hashValue, authoritySignature, timestamp);
            if (!resp.getResult()) {
                return ErrorCode.getTypeByErrorCode(resp.getErrorCode());
            }
        }
        return ErrorCode.SUCCESS;
    }

    private static ErrorCode verifyContentInner(
        CredentialPojo credential,
        String publicKey,
        boolean offline
    ) {
        ErrorCode checkResp = CredentialPojoUtils.isCredentialPojoValid(credential);
        if (ErrorCode.SUCCESS.getCode() != checkResp.getCode()) {
            return checkResp;
        }
        if (credential.getCptId() == CredentialConstant.CREDENTIAL_EMBEDDED_SIGNATURE_CPT
            .intValue()) {
            logger.error("Embedded Credential is obsoleted. Please use embedded Credential Pojo.");
            return ErrorCode.CPT_ID_ILLEGAL;
        }
        if (credential.getCptId() == CredentialConstant.CREDENTIALPOJO_EMBEDDED_SIGNATURE_CPT
            .intValue() || credential.getCptId() == CredentialConstant.EMBEDDED_TIMESTAMP_CPT
            .intValue()) {
            // This is a multi-signed Credential. We firstly verify itself (i.e. external check)
            ErrorCode errorCode = verifySingleSignedCredential(credential, publicKey, offline);
            if (errorCode != ErrorCode.SUCCESS) {
                return errorCode;
            }
            // Then, we verify its list members one-by-one
            List<Object> innerCredentialList;
            try {
                if (credential.getClaim().get("credentialList") instanceof String) {
                    // For selectively-disclosed credential, stop here. External check is enough.
                    return ErrorCode.SUCCESS;
                } else {
                    innerCredentialList = (ArrayList) credential.getClaim().get("credentialList");
                }
            } catch (Exception e) {
                logger.error("the credential claim data illegal.", e);
                return ErrorCode.CREDENTIAL_CLAIM_DATA_ILLEGAL;
            }
            for (Object innerCredentialObject : innerCredentialList) {
                // PublicKey can only be used in the passed-external check, so pass-in null key
                try {
                    CredentialPojo innerCredential;
                    if (!(innerCredentialObject instanceof CredentialPojo)) {
                        Map<String, Object> map = (Map<String, Object>) innerCredentialObject;
                        innerCredential = DataToolUtils
                            .mapToObj(map, CredentialPojo.class);
                    } else {
                        innerCredential = (CredentialPojo) innerCredentialObject;
                    }
                    errorCode = verifyContentInner(innerCredential, null, offline);
                    if (errorCode != ErrorCode.SUCCESS) {
                        return errorCode;
                    }
                } catch (Exception e) {
                    logger.error("Failed to convert credentialPojo to object.", e);
                    return ErrorCode.ILLEGAL_INPUT;
                }
            }
            return ErrorCode.SUCCESS;
        }
        return verifySingleSignedCredential(credential, publicKey, offline);
    }

    private static ErrorCode verifySingleSignedCredential(
        CredentialPojo credential,
        String publicKey,
        boolean offline
    ) {
        ErrorCode errorCode = verifyCptFormat(
            credential.getCptId(),
            credential.getClaim(),
            CredentialPojoUtils.isSelectivelyDisclosed(credential.getSalt()),
            offline
        );
        if (ErrorCode.SUCCESS.getCode() != errorCode.getCode()) {
            return errorCode;
        }
        Map<String, Object> salt = credential.getSalt();
        String rawData;
        if (CredentialPojoUtils.isEmbeddedCredential(credential)) {
            List<Object> objList = (ArrayList<Object>) credential.getClaim().get("credentialList");
            List<CredentialPojo> credentialList = new ArrayList<>();
            try {
                for (Object obj : objList) {
                    if (obj instanceof CredentialPojo) {
                        credentialList.add((CredentialPojo) obj);
                    } else {
                        credentialList.add(DataToolUtils
                            .mapToObj((HashMap<String, Object>) obj, CredentialPojo.class));
                    }
                }
            } catch (Exception e) {
                logger.error("Failed to convert credentialPojo: " + e.getMessage(), e);
                return ErrorCode.CREDENTIAL_CLAIM_DATA_ILLEGAL;
            }
            rawData = CredentialPojoUtils.getEmbeddedCredentialThumbprintWithoutSig(credentialList);
        } else {
            rawData = CredentialPojoUtils
                .getCredentialThumbprintWithoutSig(credential, salt, null);
        }
        String issuerWeid = credential.getIssuer();
        if (StringUtils.isEmpty(publicKey)) {
            // Fetch public key from chain
            ResponseData<WeIdDocument> innerResponseData =
                getWeIdService().getWeIdDocument(issuerWeid);
            if (innerResponseData.getErrorCode() != ErrorCode.SUCCESS.getCode()) {
                logger.error(
                    "Error occurred when fetching WeIdentity DID document for: {}, msg: {}",
                    issuerWeid, innerResponseData.getErrorMessage());
                return ErrorCode.getTypeByErrorCode(innerResponseData.getErrorCode());
            } else {
                WeIdDocument weIdDocument = innerResponseData.getResult();
                return DataToolUtils
                    .verifySignatureFromWeId(rawData, credential.getSignature(), weIdDocument);
            }
        } else {
            boolean result;
            try {
                result = DataToolUtils
                    .verifySignature(
                        rawData,
                        credential.getSignature(),
                        new BigInteger(publicKey)
                    );
            } catch (Exception e) {
                logger.error("[verifyContent] verify signature fail.", e);
                return ErrorCode.CREDENTIAL_SIGNATURE_BROKEN;
            }
            if (!result) {
                return ErrorCode.CREDENTIAL_SIGNATURE_BROKEN;
            }
            return ErrorCode.SUCCESS;
        }
    }


    private static ErrorCode verifyCptFormat(
        Integer cptId, Map<String, Object> claim,
        boolean isSelectivelyDisclosed,
        boolean offline
    ) {
        if (cptId == CredentialConstant.CREDENTIALPOJO_EMBEDDED_SIGNATURE_CPT.intValue()) {
            if (!claim.containsKey("credentialList")) {
                return ErrorCode.CREDENTIAL_CLAIM_DATA_ILLEGAL;
            } else {
                return ErrorCode.SUCCESS;
            }
        }
        if (cptId == CredentialConstant.EMBEDDED_TIMESTAMP_CPT.intValue()) {
            if (claim.containsKey("credentialList") && claim.containsKey("claimHash")
                && claim.containsKey("timestampAuthority") && claim.containsKey("timestamp")
                && claim.containsKey("authoritySignature")) {
                return ErrorCode.SUCCESS;
            } else {
                return ErrorCode.CREDENTIAL_CLAIM_DATA_ILLEGAL;
            }
        }
        try {
            if (offline) {
                return ErrorCode.SUCCESS;
            }
            String claimStr = DataToolUtils.serialize(claim);
            Cpt cpt = getCptService().queryCpt(cptId).getResult();
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
            if (!isSelectivelyDisclosed) {
                if (!DataToolUtils.isValidateJsonVersusSchema(claimStr, cptJsonSchema)) {
                    logger.error(ErrorCode.CREDENTIAL_CLAIM_DATA_ILLEGAL.getCodeDesc());
                    return ErrorCode.CREDENTIAL_CLAIM_DATA_ILLEGAL;
                }
            }
            return ErrorCode.SUCCESS;
        } catch (Exception e) {
            logger.error(
                "Generic error occurred during verify cpt format when verifyCredential: ", e);
            return ErrorCode.CREDENTIAL_ERROR;
        }
    }


    // TODO 【重要, 校验 零知识证明Credential】
    //
    // todo 校验零知识证明的Credential
    private static ResponseData<Boolean> verifyZkpCredential(CredentialPojo credential) {

        // 拿到 Credential 中的 Proof
        Map<String, Object> proof = credential.getProof();

        // 获取 `encodedVerificationRule` 的值
        String encodedVerificationRule = (String) proof
            .get(ParamKeyConstant.PROOF_ENCODEDVERIFICATIONRULE);

        // 获取 `verificationRequest` 的值
        String verificationRequest = (String) proof.get(ParamKeyConstant.PROOF_VERIFICATIONREQUEST);

        // todo 调用远端 根据 `encodedVerificationRule` 的值 和 `verificationRequest` 的值
        //      获取 verifierResult
        VerifierResult verifierResult =
            VerifierClient.verifyProof(encodedVerificationRule, verificationRequest);
        if (verifierResult.wedprErrorMessage == null) {
            return new ResponseData<Boolean>(true, ErrorCode.SUCCESS);
        }

        return new ResponseData<Boolean>(false, ErrorCode.CREDENTIAL_ERROR);
    }

    // 是否是 zkp Credential
    private static Boolean isZkpCredential(CredentialPojo credential) {

        List<String> types = credential.getType();
        for (String type : types) {
            if (StringUtils.equals(type, CredentialType.ZKP.getName())) {
                return true;
            }
        }
        return false;
    }

    /**
     * todo 用户创建 Credential
     * user build credential Info map and makeCredential.
     */
    private static UserResult makeCredential(
        CredentialPojo preCredential,           // 还未完成的Credential信息
        String claimJson,                       // 该Credential 中的Claim
        Integer cptId,                          // 对应Claim 的cptId, 主要用来去 chain 上查回 cpt模板对 入参的Claim做校验的
        WeIdAuthentication weIdAuthentication   // 认证方式
    ) {

        // 构建出 Credential Map
        Map<String, String> credentialInfoMap = buildCredentialInfo(preCredential, claimJson);


        // todo 根据 CPT Id 去chain 上查回, Credential 需要用的 Claim jsonSchame / CredentialTemplate的 Pubkey 和 Proof
        ResponseData<CredentialTemplateEntity> res = getCptService().queryCredentialTemplate(cptId);
        CredentialTemplateEntity credentialTemplate = res.getResult();


        // todo 妈的, 这里的细节被封装成 native 方法了 (使用了 动态库, 防止被抄袭 ??)
        //
        // todo 发起调用远端的 请求??
        UserResult userResult = UserClient.makeCredential(credentialInfoMap, credentialTemplate);

        // masterSecret is saved by User
        // todo 我草, 这里就看不懂了 `masterSecret` 和 `credentialSecretsBlindingFactors` 到底什么东西呢
        String masterSecret = userResult.masterSecret;  // 私钥? 谁的 私钥啊?
        String credentialSecretsBlindingFactors = userResult.credentialSecretsBlindingFactors;

        Map<String, String> userCredentialInfo = new HashMap<>();
        userCredentialInfo.put(ParamKeyConstant.MASTER_SECRET, masterSecret);
        userCredentialInfo.put(ParamKeyConstant.BLINDING_FACTORS, credentialSecretsBlindingFactors);
        String json = DataToolUtils.serialize(userCredentialInfo);
        String id = new StringBuffer().append(weIdAuthentication.getWeId()).append("_")
            .append(cptId).toString();
        //String id=(String)preCredential.getClaim().get(CredentialConstant.CREDENTIAL_META_KEY_ID);

        //save masterSecret and credentialSecretsBlindingFactors to persistence.
        //
        // todo 将masterSecret和credentialSecretsBlindingFactors 存入本地DB
        ResponseData<Integer> dbResp = getDataDriver()
            .saveOrUpdate(DataDriverConstant.DOMAIN_USER_MASTER_SECRET, id, json);
        if (dbResp.getErrorCode().intValue() != ErrorCode.SUCCESS.getCode()) {
            logger.error(
                "[makeCredential] save masterSecret and blindingFactors to db failed.");
            return null;
        }

        return userResult;
    }

    /**
     *
     * todo 根据 不完整的Credential (pre-credential) 和 不是最终的Claim 来构建 CredentialMap
     * build credentialInfoMap from pre-credential and claim sent by issuer.
     */
    private static Map<String, String> buildCredentialInfo(CredentialPojo preCredential,
        String claimJson) {


        // 将对应的 字段 Copy 过来, 中转变量
        //
        // Pojo 是 `Credential信息的基本数据结构`
        CredentialPojo tempCredential = DataToolUtils.clone(preCredential);

        // 将Claim 转成 Map, 这个现在  其实这个 Claim 不是最终的Claim, 这个Claim 中有些字段是 Credential 需要的
        // todo 在 Pre-Credential 中的 Claim 可能不是最终的 Claim 哦
        Map<String, Object> claim = preCredential.getClaim();

        // todo 这个用来装 最终的 Credential
        Map<String, String> credentialInfo = new HashMap<String, String>();
        Map<String, String> newCredentialInfo = new HashMap<String, String>();
        try {

            // 将 入参的ClaimJson 信息转成 ClaimMap
            Map<String, Object> claimMap = DataToolUtils.deserialize(claimJson, HashMap.class);

            // 将入参的 ClaimJson 的Map信息存入 中转变量的 tempCredential
            tempCredential.setClaim(claimMap);

            // 取出 之前在 Pre-Credential 的 Claim中的 `@content` 的值 (它其实是 该 Credential 需要用的)
            tempCredential.setContext(
                String.valueOf(claim.get(CredentialConstant.CREDENTIAL_META_KEY_CONTEXT)));

            // 取出 之前在 Pre-Credential 的 Claim中的 `cptId` 的值 (它其实是 该 Credential 需要用的)
            tempCredential
                .setCptId((Integer) claim.get(CredentialConstant.CREDENTIAL_META_KEY_CPTID));

            // 同上 (失效日期)
            Long newExpirationDate =
                DateUtils.convertToNoMillisecondTimeStamp(
                    (Long) (claim.get(CredentialConstant.CREDENTIAL_META_KEY_EXPIRATIONDATE)));
            tempCredential.setExpirationDate(newExpirationDate);

            // 同上 (Credential 的Id)
            tempCredential
                .setId(String.valueOf(claim.get(CredentialConstant.CREDENTIAL_META_KEY_ID)));

            // 同上 (发行日期)
            Long newIssuanceDate =
                DateUtils.convertToNoMillisecondTimeStamp(
                    (Long) (claim.get(CredentialConstant.CREDENTIAL_META_KEY_ISSUANCEDATE)));
            tempCredential.setIssuanceDate(newIssuanceDate);

            // 同上 (发行人的 WeId)
            tempCredential.setIssuer(
                String.valueOf(claim.get(CredentialConstant.CREDENTIAL_META_KEY_ISSUER)));
            credentialInfo = JsonUtil.credentialToMonolayer(tempCredential);
            for (Map.Entry<String, String> entry : credentialInfo.entrySet()) {
                newCredentialInfo.put(entry.getKey(), String.valueOf(entry.getValue()));
            }
        } catch (IOException e) {
            logger.error("[buildCredentialInfo] build credential info map failed.", e);
        }
        return newCredentialInfo;
    }

    private static void processZkpPolicy(
        ClaimPolicy claimPolicy,                // 零知识证明的  Claim 的 policy
        List<String> revealedAttributeList,     // 需要回填的 显露列表
        List<Predicate> predicateList) {        // 需要回填的 谓语列表

        String policyJson = null;
        try {
            policyJson = JsonUtil.claimPolicyToMonolayer(claimPolicy);
        } catch (IOException e) {
            e.printStackTrace();
        }
        Map<String, Object> disclosureMap = DataToolUtils
            .deserialize(policyJson, HashMap.class);

        // 遍历
        for (Map.Entry<String, Object> entry : disclosureMap.entrySet()) {

            String key = entry.getKey();
            Object value = entry.getValue();  //
            if (value instanceof Map) {       // 如果 value 是一个 map 的形式, 那么是一个 表达式
                processExpression(key, (HashMap) value, predicateList);
            } else if (value instanceof Integer) {
                processBaseValue(key, String.valueOf(value), revealedAttributeList);
            } else if (value instanceof String) {
                processBaseValue(key, (String) value, revealedAttributeList);
            } else {
                return;
            }
        }

    }

    // 处理 表达式 (zkp Claim policy 相关)
    private static void processExpression(
        String key,                         // Claim 中的 key
        Map<String, Object> expression,     // Claim 中的 value
        List<Predicate> predicateList) {

        // 遍历 表达式 (里面存着一堆 谓语类型)
        for (Map.Entry<String, Object> entry : expression.entrySet()) {

            String predicateKey = entry.getKey();
            Object predicateValue = entry.getValue();
            PredicateType predicateType = getPredicateType(predicateKey);

            // 根据当前 key  和 谓语Type, 谓语的value, 生成 谓语
            Predicate predicate = Utils.makePredicate(key, predicateType, (Integer) predicateValue);
            predicateList.add(predicate);
        }
    }

    private static void processBaseValue(
        String key,
        String value,
        List<String> revealedAttributeList) {
        if (StringUtils.equals(value, DISCLOSED)) {
            revealedAttributeList.add(key);
        }
    }

    // 根据 表达式的 key 生成对应的 表达式 类型
    private static PredicateType getPredicateType(String predicate) {

        switch (predicate) {
            case "EQ":
                return PredicateType.EQ;
            case "GE":
                return PredicateType.GE;
            case "GT":
                return PredicateType.GT;
            case "LE":
                return PredicateType.LE;
            case "LT":
                return PredicateType.LT;
            default:
                return null;

        }
    }

    private static boolean isLiteCredential(CredentialPojo credential) {

        List<String> types = credential.getType();
        if (types.contains(CredentialType.LITE1.getName())) {
            return true;
        }
        return false;
    }

    // todo 校验 Lite 类型的 Credential
    private static ResponseData<Boolean> verifyLiteCredential(
        CredentialPojo credential,
        String publicKey) {
        // Lite Credential only contains limited areas (others truncated)
        if (credential.getCptId() == null || credential.getCptId().intValue() < 0) {
            return new ResponseData<>(false, ErrorCode.CPT_ID_ILLEGAL);
        }
        if (!WeIdUtils.isWeIdValid(credential.getIssuer())) {
            return new ResponseData<>(false, ErrorCode.CREDENTIAL_ISSUER_INVALID);
        }
        if (credential.getClaim() == null || credential.getClaim().size() == 0) {
            return new ResponseData<>(false, ErrorCode.CREDENTIAL_CLAIM_NOT_EXISTS);
        }
        if (credential.getProof() == null || StringUtils.isEmpty(credential.getSignature())) {
            return new ResponseData<>(false, ErrorCode.CREDENTIAL_SIGNATURE_NOT_EXISTS);
        }
        String rawData = CredentialPojoUtils.getLiteCredentialThumbprintWithoutSig(credential);
        if (!StringUtils.isBlank(publicKey)) {
            boolean result;
            try {
                // For Lite CredentialPojo, we begin to use Secp256k1 verify to fit external type
                result = DataToolUtils.secp256k1VerifySignature(rawData, credential.getSignature(),
                    new BigInteger(publicKey));
            } catch (Exception e) {
                logger.error("[verifyContent] verify signature fail.", e);
                return new ResponseData<Boolean>(false, ErrorCode.CREDENTIAL_SIGNATURE_BROKEN);
            }
            if (!result) {
                return new ResponseData<Boolean>(false, ErrorCode.CREDENTIAL_SIGNATURE_BROKEN);
            }
            return new ResponseData<Boolean>(true, ErrorCode.SUCCESS);
        }
        String issuerWeid = credential.getIssuer();
        // Fetch public key from chain
        ResponseData<WeIdDocument> innerResponseData =
            getWeIdService().getWeIdDocument(issuerWeid);
        if (innerResponseData.getErrorCode() != ErrorCode.SUCCESS.getCode()) {
            logger.error(
                "Error occurred when fetching WeIdentity DID document for: {}, msg: {}",
                issuerWeid, innerResponseData.getErrorMessage());
            return new ResponseData<Boolean>(false,
                ErrorCode.getTypeByErrorCode(innerResponseData.getErrorCode()));
        } else {
            WeIdDocument weIdDocument = innerResponseData.getResult();
            ErrorCode verifyErrorCode = DataToolUtils
                .verifySecp256k1SignatureFromWeId(rawData, credential.getSignature(), weIdDocument);
            if (verifyErrorCode.getCode() != ErrorCode.SUCCESS.getCode()) {
                return new ResponseData<Boolean>(false, verifyErrorCode);
            }
            return new ResponseData<Boolean>(true, ErrorCode.SUCCESS);

        }
    }

    /**
     * todo 验证授权令牌 Credential 中的授权信息
     *
     * Verify the authorization info in an authorization token credential.
     *
     * @param authInfo the auth info in CPT101 format
     * @return success if valid, specific error codes otherwise
     */
    public static ErrorCode verifyAuthInfo(Cpt101 authInfo) {
        if (authInfo == null) {
            return ErrorCode.ILLEGAL_INPUT;
        }

        String serviceUrl = authInfo.getServiceUrl();
        String resourceId = authInfo.getResourceId();
        Long duration = authInfo.getDuration();
        if (!CredentialUtils.isValidUuid(resourceId)) {
            logger.error("Resource ID illegal: is not a valid UUID.");
            return ErrorCode.ILLEGAL_INPUT;
        }
        if (!DataToolUtils.isValidEndpointUrl(serviceUrl)) {
            logger.error("Service URL illegal.");
            return ErrorCode.ILLEGAL_INPUT;
        }
        if (duration < 0) {
            logger.error("Auth token duration of validity illegal: already expired.");
            return ErrorCode.CREDENTIAL_EXPIRE_DATE_ILLEGAL;
        }

        String fromWeId = authInfo.getFromWeId();
        String toWeId = authInfo.getToWeId();
        if (fromWeId.equalsIgnoreCase(toWeId)) {
            logger.error("FromWeId and ToWeId must be different.");
            return ErrorCode.AUTHORIZATION_FROM_TO_MUST_BE_DIFFERENT;
        }
        ResponseData<Boolean> existResp = getWeIdService().isWeIdExist(fromWeId);
        if (!existResp.getResult()) {
            logger.error("From WeID illegal: {}", existResp.getErrorMessage());
            return ErrorCode.getTypeByErrorCode(existResp.getErrorCode());
        }
        existResp = getWeIdService().isWeIdExist(toWeId);
        if (!existResp.getResult()) {
            logger.error("To WeID illegal: {}", existResp.getErrorMessage());
            return ErrorCode.getTypeByErrorCode(existResp.getErrorCode());
        }
        return ErrorCode.SUCCESS;
    }


    // TODO 【超级重要】
    //      这个就是 生成 原始的 Credential 了
    //
    // todo 根据传入的claim对象生成Credential (注意, 这个不传 Salt)
    //
    // todo 需要自己算 slat算出 salt
    //
    // todo 依赖外部入参 构造 Credential
    /* (non-Javadoc)
     * @see com.webank.weid.rpc.CredentialPojoService#createCredential(
     *          com.webank.weid.protocol.request.CreateCredentialPojoArgs
     *      )
     */
    @Override
    public ResponseData<CredentialPojo> createCredential(CreateCredentialPojoArgs args) {

        try {
            // 形式化验证
            ErrorCode innerResponseData =
                CredentialPojoUtils.isCreateCredentialPojoArgsValid(args);
            if (ErrorCode.SUCCESS.getCode() != innerResponseData.getCode()) {
                logger.error("Create Credential Args illegal: {}",
                    innerResponseData.getCodeDesc());
                return new ResponseData<>(null, innerResponseData);
            }
            
            // Credential信息的基本数据结构
            //
            // TODO 最后 返回的  Credential
            CredentialPojo result = new CredentialPojo();
            // 设置Credential 默认的 `@contant` 字段的 URL
            String context = CredentialUtils.getDefaultCredentialContext();
            result.setContext(context);

            // UUID 生成 Credential Id
            if (StringUtils.isBlank(args.getId())) {
                result.setId(UUID.randomUUID().toString());
            } else {
                result.setId(args.getId());
            }
            result.setCptId(args.getCptId());
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

            // 使用 认证方式 中的 PriKey 验证当前 发行者的WeId
            if (!WeIdUtils.validatePrivateKeyWeIdMatches(
                args.getWeIdAuthentication().getWeIdPrivateKey(),
                args.getIssuer())) {
                logger.error("Create Credential, private key does not match the current weid.");
                return new ResponseData<>(null, ErrorCode.WEID_PRIVATEKEY_DOES_NOT_MATCH);
            }
            result.setIssuer(args.getIssuer());
            Long newExpirationDate =
                DateUtils.convertToNoMillisecondTimeStamp(args.getExpirationDate());
            if (newExpirationDate == null) {
                logger.error("Create Credential Args illegal.");
                return new ResponseData<>(null, ErrorCode.CREDENTIAL_EXPIRE_DATE_ILLEGAL);
            } else {
                result.setExpirationDate(newExpirationDate);
            }
            result.addType(CredentialConstant.DEFAULT_CREDENTIAL_TYPE);
            result.addType(args.getType().getName());

            Object claimObject = args.getClaim();
            String claimStr = null;
            if (!(claimObject instanceof String)) {
                claimStr = DataToolUtils.serialize(claimObject);
            } else {
                claimStr = (String) claimObject;
            }

            HashMap<String, Object> claimMap = DataToolUtils.deserialize(claimStr, HashMap.class);
            result.setClaim(claimMap);

            String privateKey = args.getWeIdAuthentication().getWeIdPrivateKey().getPrivateKey();

            // todo 如果 类型是 lite1
            if (StringUtils.equals(args.getType().getName(), CredentialType.LITE1.getName())) {
                // TODO 创建lite1类型的Credential  (主要是 添加 PriKey 的签名)
                return createLiteCredential(result, privateKey);
            }


            // todo 否则 不是 lite类型, ...

            // TODO 这里 只是将 Claim 中的 field 字段 copy到 saltMap中了, 但是还没算 salt
            Map<String, Object> saltMap = DataToolUtils.clone(claimMap); // todo 需要自己算 slat

            // todo ##################################################
            // todo ############## 这里才是, 随机算 salt  ##############
            // todo ##################################################
            generateSalt(saltMap, null); // todo 添加 随机 salt

            // todo 根据 saltMap 计算出对应的 Claim 的Hash (Claim 的字段全部加salt算Hash 哦)
            String rawData = CredentialPojoUtils
                .getCredentialThumbprintWithoutSig(result, saltMap, null);

            // todo 使用当前 issuer 的priKey 对整个 Credential 做签名
            String signature = DataToolUtils.sign(rawData, privateKey);

            // --------------------------
            // todo credential的proof 中 添加 签名相关的信息

            result.putProofValue(ParamKeyConstant.PROOF_CREATED, result.getIssuanceDate());
            // 提取 认证方式中的 PubKey的 index
            String weIdPublicKeyId = args.getWeIdAuthentication().getWeIdPublicKeyId();
            result.putProofValue(ParamKeyConstant.PROOF_CREATOR, weIdPublicKeyId);

            // 默认是 ECDSA 算法类型
            String proofType = CredentialProofType.ECDSA.getTypeName();
            result.putProofValue(ParamKeyConstant.PROOF_TYPE, proofType);
            result.putProofValue(ParamKeyConstant.PROOF_SIGNATURE, signature);
            // 最后将 salt 也加入 proof 中
            result.setSalt(saltMap);

            ResponseData<CredentialPojo> responseData = new ResponseData<>(
                result,
                ErrorCode.SUCCESS
            );

            return responseData;
        } catch (Exception e) {
            logger.error("Generate Credential failed due to system error. ", e);
            return new ResponseData<>(null, ErrorCode.CREDENTIAL_ERROR);
        }
    }

    // TODO 创建lite1类型的Credential  (主要是 添加 PriKey 的签名)
    private ResponseData<CredentialPojo> createLiteCredential(CredentialPojo credentialPojo,
        String privateKey) {

        String rawData = CredentialPojoUtils.getLiteCredentialThumbprintWithoutSig(credentialPojo);

        // For Lite CredentialPojo, we begin to use Secp256k1 format signature to fit external type
        String signature = DataToolUtils.secp256k1Sign(rawData, new BigInteger(privateKey, 10));

        String proofType = CredentialProofType.ECDSA.getTypeName();
        credentialPojo.putProofValue(ParamKeyConstant.PROOF_TYPE, proofType);
        credentialPojo.putProofValue(ParamKeyConstant.PROOF_SIGNATURE, signature);
        ResponseData<CredentialPojo> responseData = new ResponseData<>(
            credentialPojo,
            ErrorCode.SUCCESS
        );
        return responseData;
    }

    /**
     * TODO 多签，在原凭证 (Credential) 列表的基础上，创建包裹成一个新的多签凭证 (Muti-sign Credential)，由传入的私钥所签名。
     *      此凭证的CPT为一个固定值 (106 或者 107 ??)。【在验证一个多签凭证时，会迭代验证其包裹的所有子凭证】。
     *      本接口【不支持】创建选【择性披露的多签凭证】。
     *
     * Add an extra signer and signature to a Credential. Multiple signatures will be appended in an
     * embedded manner.
     *
     * TODO 向凭据 (Credential) 添加 额外的签名者和签名。 多个签名将以嵌入方式添加
     *
     *
     *  {
     *      "claim": {
     *        "credentialList": [
     *          {
     *            "claim": {
     *              "age": 1,
     *              "gender": "F",
     *              "id": "did:weid:1000:1:0xa4c2666560499868baf1906941f806b6d1c26e33",
     *              "name": "1"
     *            },
     *            "context": "https:\/\/github.com\/WeBankFinTech\/WeIdentity\/blob\/master\/context\/v1",
     *            "cptId": 2000087,
     *            "expirationDate": 1567491752,
     *            "id": "6ea6e209-10e9-4a93-b6be-12af1a32655b",
     *            "issuanceDate": 1567405352,
     *            "issuer": "did:weid:1000:1:0xa4c2666560499868baf1906941f806b6d1c26e33",
     *            "proof": {
     *              "created": 1567405352,
     *              "creator": "did:weid:1000:1:0xa4c2666560499868baf1906941f806b6d1c26e33#keys-0",
     *              "salt": {
     *                "age": "yOwN7",
     *                "gender": "jjB85",
     *                "id": "BmRYI",
     *                "name": "BjYqF"
     *              },
     *              "signatureValue": "G+SNG3rBZNDvRNgRtJugPtX1FmE8XJIkV4CGPK\/nt\/breIPMJ5wYxImTp2QAxBUe5HMwCe9PPGhhMJJAazM5u9k=",
     *              "type": "Secp256k1"
     *            },
     *            "type": [
     *              "VerifiableCredential"
     *            ]
     *          },
     *          {
     *            "claim": {
     *              "age": 1,
     *              "gender": "F",
     *              "id": "did:weid:1000:1:0x309320a01f215a380c6950e80a89181ad8a8cd53",
     *              "name": "1"
     *            },
     *            "context": "https:\/\/github.com\/WeBankFinTech\/WeIdentity\/blob\/master\/context\/v1",
     *            "cptId": 2000087,
     *            "expirationDate": 1567491842,
     *            "id": "a3544a9c-6cb6-4688-9622-bb935fb0d93f",
     *            "issuanceDate": 1567405355,
     *            "issuer": "did:weid:1000:1:0x309320a01f215a380c6950e80a89181ad8a8cd53",
     *            "proof": {
     *              "created": 1567405355,
     *              "creator": "did:weid:1000:1:0x309320a01f215a380c6950e80a89181ad8a8cd53#keys-0",
     *              "salt": {
     *                "age": "5nImi",
     *                "gender": "Me224",
     *                "id": "5pYs2",
     *                "name": "z6VmW"
     *              },
     *              "signatureValue": "HC8OAG\/dRmteGSIGWIDekp8fC1KJI8EEDZBb29HiTLXvVj350l9yTOHeGSBCr2VRY\/DSHT5ONjlvcrO4Mqa3Auo=",
     *              "type": "Secp256k1"
     *            },
     *            "type": [
     *              "VerifiableCredential"
     *            ]
     *          }
     *        ]
     *      },
     *      "context": "https:\/\/github.com\/WeBankFinTech\/WeIdentity\/blob\/master\/context\/v1",
     *      "cptId": 107,
     *      "expirationDate": 1567491842,
     *      "id": "ad5d5a54-4574-4b3b-b1df-9d0687b6a0ac",
     *      "issuanceDate": 1567405359,
     *      "issuer": "did:weid:1000:1:0x4e9a111867ed6370e1e23f7a79426f6649eb78c6",
     *      "proof": {
     *        "created": 1567405359,
     *        "creator": "did:weid:1000:1:0x4e9a111867ed6370e1e23f7a79426f6649eb78c6#keys-0",
     *        "salt": {
     *          "credentialList": ""
     *        },
     *        "signatureValue": "HC1y3rfyb\/2sg+E2Uulczm8VDtmQ6VrU\/9ow4e4nP3lVUOv4Gz41pfBrJHnV4wQoUbQsCYpezFx5sdaUwUILV1I=",
     *        "type": "Secp256k1"
     *      },
     *      "type": [
     *        "VerifiableCredential"
     *      ]
     *    }
     *
     *
     * @param credentialList original credential list
     * @param callerAuth the passed-in privateKey and WeID bundle to sign
     * @return the modified CredentialWrapper
     */
    @Override
    public ResponseData<CredentialPojo> addSignature(
        List<CredentialPojo> credentialList,
        WeIdAuthentication callerAuth) {
        if (credentialList == null || credentialList.size() == 0
            || CredentialPojoUtils.isWeIdAuthenticationValid(callerAuth) != ErrorCode.SUCCESS) {
            return new ResponseData<>(null, ErrorCode.ILLEGAL_INPUT);
        }
        CredentialPojo result = new CredentialPojo();
        result.setCptId(CredentialConstant.CREDENTIALPOJO_EMBEDDED_SIGNATURE_CPT);
        result.setIssuanceDate(DateUtils.getNoMillisecondTimeStamp());
        result.setId(UUID.randomUUID().toString());
        result.setContext(CredentialUtils.getDefaultCredentialContext());
        Long expirationDate = 0L;
        for (CredentialPojo arg : credentialList) {
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
        if (!WeIdUtils.validatePrivateKeyWeIdMatches(
            callerAuth.getWeIdPrivateKey(),
            callerAuth.getWeId())) {
            logger.error("Create Credential, private key does not match the current weid.");
            return new ResponseData<>(null, ErrorCode.WEID_PRIVATEKEY_DOES_NOT_MATCH);
        }
        if (!getWeIdService().isWeIdExist(callerAuth.getWeId()).getResult()) {
            return new ResponseData<>(null, ErrorCode.WEID_DOES_NOT_EXIST);
        }
        String privateKey = callerAuth.getWeIdPrivateKey().getPrivateKey();
        ECKeyPair keyPair = ECKeyPair.create(new BigInteger(privateKey));
        String keyWeId = WeIdUtils
            .convertAddressToWeId(new Address(Keys.getAddress(keyPair)).toString());
        result.setIssuer(keyWeId);
        result.addType(CredentialConstant.DEFAULT_CREDENTIAL_TYPE);

        List<Map> trimmedCredentialMapList = trimCredentialList(credentialList);

        // The claim will be the wrapper of the to-be-signed credentialpojos
        HashMap<String, Object> claim = new HashMap<>();
        claim.put("credentialList", trimmedCredentialMapList);
        result.setClaim(claim);

        // For embedded signature, salt here is totally meaningless - hence we left it blank
        Map<String, Object> saltMap = DataToolUtils.clone(claim);
        CredentialPojoUtils.clearMap(saltMap);
        String rawData = CredentialPojoUtils
            .getEmbeddedCredentialThumbprintWithoutSig(credentialList);
        String signature = DataToolUtils.sign(rawData, privateKey);

        result.putProofValue(ParamKeyConstant.PROOF_CREATED, result.getIssuanceDate());

        String weIdPublicKeyId = callerAuth.getWeIdPublicKeyId();
        result.putProofValue(ParamKeyConstant.PROOF_CREATOR, weIdPublicKeyId);

        String proofType = CredentialProofType.ECDSA.getTypeName();
        result.putProofValue(ParamKeyConstant.PROOF_TYPE, proofType);
        result.putProofValue(ParamKeyConstant.PROOF_SIGNATURE, signature);
        result.setSalt(saltMap);

        return new ResponseData<>(result, ErrorCode.SUCCESS);
    }

    private List<Map> trimCredentialList(List<CredentialPojo> credentialList) {
        List<CredentialPojo> trimmedCredentialList = new ArrayList<>();
        for (CredentialPojo arg : credentialList) {
            boolean found = false;
            for (CredentialPojo credAlive : trimmedCredentialList) {
                if (CredentialPojoUtils.isEqual(arg, credAlive)) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                ErrorCode errorCode = CredentialPojoUtils.isCredentialPojoValid(arg);
                if (errorCode != ErrorCode.SUCCESS) {
                    return null;
                }
                trimmedCredentialList.add(arg);
            }
        }

        List<Map> trimmedCredentialMapList = new ArrayList<>();
        for (CredentialPojo credAlive : trimmedCredentialList) {
            try {
                trimmedCredentialMapList.add(DataToolUtils.objToMap(credAlive));
            } catch (Exception e) {
                logger.error("Failed to convert Credential to map structure.", e);
                return null;
            }
        }
        return trimmedCredentialMapList;
    }

    /* (non-Javadoc)
     * @see com.webank.weid.rpc.CredentialPojoService#createSelectiveCredential(
     *          com.webank.weid.protocol.base.CredentialPojo,
     *          com.webank.weid.protocol.base.ClaimPolicy
     *      )
     */
    // todo 通过 原始凭证 和 披露策略 ，创建选择性披露的Credential
    //
    // todo 从外面 传进来的  salt
    //
    // todo 需要生成选择性披露的 原始Credential
    //
    // todo 对于已经创建好的选择性披露凭证，不允许再次进行选择性披露
    @Override
    public ResponseData<CredentialPojo> createSelectiveCredential(
        CredentialPojo credential,              // 外面入参的 需要做选择性披露的 原始 Credential  todo 里面包含了 原始的Claim各个字段的 原始 salt
        ClaimPolicy claimPolicy) {              // 选择性披露策略

        if (credential == null) {
            logger.error("[createSelectiveCredential] input credential is null");
            return new ResponseData<CredentialPojo>(null, ErrorCode.ILLEGAL_INPUT);
        }

        // 看下 是 LITE1 类型 还是 ZKP 类型
        // todo LITE1 和 ZKP 不具备 选择性披露性质, 他们只用于 零知识证明或者具备密码学的 Credential
        if (credential.getType() != null 
            && (credential.getType().contains(CredentialType.LITE1.getName()) 
            || credential.getType().contains(CredentialType.ZKP.getName()))) {
            logger.error(
                "[createSelectiveCredential] the credential does not support selective "
                    + "disclosure, type = {}.", credential.getType());
            return new ResponseData<CredentialPojo>(null,
                ErrorCode.CREDENTIAL_NOT_SUPPORT_SELECTIVE_DISCLOSURE);
        }

        // todo #############################################
        // todo #############################################
        // todo #############################################
        // todo
        // todo 只有 ORIGINAL 类型的 Credential 具备选择性披露
        // todo
        // todo #############################################
        // todo #############################################
        // todo #############################################
        try {

            // todo 一个 深拷贝
            CredentialPojo credentialClone = DataToolUtils.clone(credential);

            // 形式校验
            ErrorCode checkResp = CredentialPojoUtils.isCredentialPojoValid(credentialClone);
            if (ErrorCode.SUCCESS.getCode() != checkResp.getCode()) {
                return new ResponseData<CredentialPojo>(null, checkResp);
            }
            // cpt Id 不能等于 107
            if (credentialClone.getCptId()
                .equals(CredentialConstant.CREDENTIALPOJO_EMBEDDED_SIGNATURE_CPT)) {
                return new ResponseData<>(null, ErrorCode.CPT_ID_ILLEGAL);
            }

            // claim 的选择性披露 policy 不可为空
            if (claimPolicy == null) {
                logger.error("[createSelectiveCredential] claimPolicy is null.");
                return new ResponseData<CredentialPojo>(null,
                    ErrorCode.CREDENTIAL_CLAIM_POLICY_NOT_EXIST);
            }

            // TODO #####################################################
            // TODO #####################################################
            // TODO
            // TODO 逐个检查 saltMap 中的 k-v 中的 value, 如果有value 是 "0" 值的话, 说明已经做过选择性披露了
            //
            // TODO 因为做过选择性披露的话, saltMap 中 对应 k-v 的value 会被置为 “0” 值
            // TODO
            // TODO #####################################################
            // TODO #####################################################
            if (CredentialPojoUtils.isSelectivelyDisclosed(credential.getSalt())) {
                return new ResponseData<CredentialPojo>(null, ErrorCode.CREDENTIAL_RE_DISCLOSED);
            }

            // todo 获取当前 policy 中的 选择性披露的字段  jsonStr
            String disclosure = claimPolicy.getFieldsToBeDisclosed();

            // todo  由此可见,  saltMap 也是从外面传进来的
            Map<String, Object> saltMap = credentialClone.getSalt();
            Map<String, Object> claim = credentialClone.getClaim();

            // 转化成 map 形式
            Map<String, Object> disclosureMap = DataToolUtils
                .deserialize(disclosure, HashMap.class);

            // todo 校验claim、salt和disclosureMap的格式是否一致
            if (!validCredentialMapArgs(claim, saltMap, disclosureMap)) {
                logger.error(
                    "[createSelectiveCredential] create failed. message is {}",
                    ErrorCode.CREDENTIAL_POLICY_FORMAT_DOSE_NOT_MATCH_CLAIM.getCodeDesc()
                );
                return new ResponseData<CredentialPojo>(null,
                    ErrorCode.CREDENTIAL_POLICY_FORMAT_DOSE_NOT_MATCH_CLAIM);
            }
            // 补 policy todo  向 disclosureMap 中补充缺失的key
            addKeyToPolicy(disclosureMap, claim);
            // 对 claim 中的非披露字段做 加盐算Hash处理
            addSelectSalt(disclosureMap, saltMap, claim, false);

            // 给 Credential 的proof 中的salt 字段设置 (一个 salt Map)
            // todo  但是这里的 salt Map 中 对应 不需要披露字段的 salt 已经被 清空了,
            //       被计算了Hash 的Claim字段对应的 salt 的值, 被置为 "0"
            //
            // todo  但是, map 是个引用, 所以这里 设置 saltMap 有啥用 ??
            //
            //
            // todo  问: 如果要设置的话 为啥 claim 不也一起 在设置一编 ?
            //
            // todo 答: 是因为 salt 是 proof 中的, 而 proof 本身也是个 Map , 所以 salt 是个 map 中map 的原因么 ??
            //          而 claim 是 Credential 的一个字段么 ??
            credentialClone.setSalt(saltMap);

            //
            ResponseData<CredentialPojo> response = new ResponseData<CredentialPojo>();
            response.setResult(credentialClone);
            response.setErrorCode(ErrorCode.SUCCESS);
            return response;
        } catch (DataTypeCastException e) {
            logger.error("Generate SelectiveCredential failed, "
                + "credential disclosure data type illegal. ", e);
            return new ResponseData<>(null, ErrorCode.CREDENTIAL_DISCLOSURE_DATA_TYPE_ILLEGAL);
        } catch (WeIdBaseException e) {
            logger.error("Generate SelectiveCredential failed, "
                + "policy disclosurevalue illegal. ", e);
            return new ResponseData<>(null, ErrorCode.CREDENTIAL_POLICY_DISCLOSUREVALUE_ILLEGAL);
        } catch (Exception e) {
            logger.error("Generate SelectiveCredential failed due to system error. ", e);
            return new ResponseData<>(null, ErrorCode.CREDENTIAL_ERROR);
        }
    }

    /**
     * TODO 传入CredentialPojo信息生成CredentialPojo整体的Hash值，一般在生成Evidence时调用
     *
     * Get the full hash value of a CredentialPojo. All fields in the CredentialPojo will be
     * included. This method should be called when creating and verifying the Credential Evidence
     * and the result is selectively-disclosure irrelevant.
     *
     * TODO 获取CredentialPojo的完整 Hash。
     *      CredentialPojo中的【所有字段】都将包括在内。
     *      【创建】和 【验证】 Evidence 时应调用此方法，【并且结果与选择披露无关】.
     *
     * @param credentialPojo the args
     * @return the Credential Hash value
     */
    @Override
    public ResponseData<String> getCredentialPojoHash(CredentialPojo credentialPojo) {
        // todo  校验 Credential 是否可用
        ErrorCode innerResponse = CredentialPojoUtils.isCredentialPojoValid(credentialPojo);
        if (ErrorCode.SUCCESS.getCode() != innerResponse.getCode()) {
            logger.error("Create Evidence input format error!");
            return new ResponseData<>(StringUtils.EMPTY, innerResponse);
        }

        // TODO 根据入参的 Credential 生成 对应的 Hash
        //      其中 salt 已经包含在 Credential 中了
        return new ResponseData<>(CredentialPojoUtils.getCredentialPojoHash(credentialPojo, null),
            ErrorCode.SUCCESS);
    }

    // todo 验证credential
    /* (non-Javadoc)
     * @see com.webank.weid.rpc.CredentialPojoService#verify(
     *          java.lang.String,
     *          com.webank.weid.protocol.base.CredentialPojo
     *      )
     */
    @Override
    public ResponseData<Boolean> verify(String issuerWeId, CredentialPojo credential) {

        if (credential == null) {
            logger.error("[verify] The input credential is invalid.");
            return new ResponseData<Boolean>(false, ErrorCode.ILLEGAL_INPUT);
        }

        if (isZkpCredential(credential)) {
            return verifyZkpCredential(credential);
        }

        String issuerId = credential.getIssuer();
        if (!StringUtils.equals(issuerWeId, issuerId)) {
            logger.error("[verify] The input issuer weid is not match the credential's.");
            return new ResponseData<Boolean>(false, ErrorCode.CREDENTIAL_ISSUER_MISMATCH);
        }
        if (isLiteCredential(credential)) {
            return verifyLiteCredential(credential, null);
        }
        ErrorCode errorCode = verifyContent(credential, null, false);
        if (errorCode.getCode() != ErrorCode.SUCCESS.getCode()) {
            logger.error("[verify] credential verify failed. error message :{}", errorCode);
            return new ResponseData<Boolean>(false, errorCode);
        }
        return new ResponseData<Boolean>(true, ErrorCode.SUCCESS);
    }


    // todo 使用 指定公钥验证credentialWrapper
    /* (non-Javadoc)
     * @see com.webank.weid.rpc.CredentialPojoService#verify(
     *          com.webank.weid.protocol.base.CredentialPojo,
     *          com.webank.weid.protocol.base.WeIdPublicKey
     *      )
     */
    @Override
    public ResponseData<Boolean> verify(
        WeIdPublicKey issuerPublicKey,
        CredentialPojo credential) {

        String publicKey = issuerPublicKey.getPublicKey();
        if (StringUtils.isEmpty(publicKey)) {
            return new ResponseData<Boolean>(false, ErrorCode.CREDENTIAL_PUBLIC_KEY_NOT_EXISTS);
        }
        if (isLiteCredential(credential)) {
            return verifyLiteCredential(credential, issuerPublicKey.getPublicKey());
        }
        ErrorCode errorCode = verifyContent(credential, publicKey, false);
        if (errorCode.getCode() != ErrorCode.SUCCESS.getCode()) {
            return new ResponseData<Boolean>(false, errorCode);
        }
        return new ResponseData<Boolean>(true, ErrorCode.SUCCESS);
    }

    // todo 校验 Presentation
    /* (non-Javadoc)
     * @see com.webank.weid.rpc.CredentialPojoService#verify(
     *          java.lang.String,
     *          com.webank.weid.protocol.base.PresentationPolicyE,
     *           com.webank.weid.protocol.base.Challenge,
     *           com.webank.weid.protocol.base.PresentationE
     *       )
     */
    @Override
    public ResponseData<Boolean> verify(
        String presenterWeId,
        PresentationPolicyE presentationPolicyE,
        Challenge challenge,
        PresentationE presentationE) {

        List<String> typeList = presentationE.getType();
        if (typeList.contains(CredentialConstant.PRESENTATION_PDF)) {
            logger.error("[verify] please use verifyPresentationFromPDF function.");
            return new ResponseData<>(false, ErrorCode.CREDENTIAL_USE_VERIFY_FUNCTION_ERROR);
        }

        ErrorCode errorCode =
            checkInputArgs(presenterWeId, presentationPolicyE, challenge, presentationE);
        if (errorCode.getCode() != ErrorCode.SUCCESS.getCode()) {
            logger.error("[verify] checkInputArgs fail.");
            return new ResponseData<Boolean>(false, errorCode);
        }

        //verify cptId of presentationE
        List<CredentialPojo> credentialList = presentationE.getVerifiableCredential();
        Map<Integer, ClaimPolicy> policyMap = presentationPolicyE.getPolicy();
        ErrorCode verifyCptIdresult =
            this.verifyCptId(policyMap, credentialList);
        if (verifyCptIdresult.getCode() != ErrorCode.SUCCESS.getCode()) {
            logger.error("[verify] verify cptId failed.");
            return new ResponseData<Boolean>(false, verifyCptIdresult);
        }
        try {
            for (CredentialPojo credential : credentialList) {
                //verify policy
                Integer cptId = credential.getCptId();
                ClaimPolicy claimPolicy = policyMap.get(cptId);
                if (claimPolicy != null) {
                    ErrorCode verifypolicyResult = this
                        .verifyPolicy(credential, claimPolicy, presenterWeId);
                    if (verifypolicyResult.getCode() != ErrorCode.SUCCESS.getCode()) {
                        logger.error("[verify] verify policy {} failed.", policyMap);
                        return new ResponseData<Boolean>(false, verifypolicyResult);
                    }
                }
                //verify credential
                //
                // TODO 如果是支持 零知识 证明的 Credential 的话
                if (isZkpCredential(credential)) {
                    return verifyZkpCredential(credential);

                }
                ErrorCode verifyCredentialResult = verifyContent(credential, null, false);
                if (verifyCredentialResult.getCode() != ErrorCode.SUCCESS.getCode()) {
                    logger.error(
                        "[verify] verify credential {} failed.", credential);
                    return new ResponseData<Boolean>(false, verifyCredentialResult);
                }
            }
            return new ResponseData<Boolean>(true, ErrorCode.SUCCESS);
        } catch (Exception e) {
            logger.error(
                "[verify] verify credential error.", e);
            return new ResponseData<Boolean>(false, ErrorCode.UNKNOW_ERROR);
        }
    }

    /* (non-Javadoc)
     * @see com.webank.weid.rpc.CredentialPojoService#verify(
     *          com.webank.weid.protocol.base.CredentialPojo,
     *          com.webank.weid.protocol.base.WeIdPublicKey
     *      )
     */
    @Override
    public ResponseData<Boolean> verifyOffline(
        WeIdPublicKey issuerPublicKey,
        CredentialPojo credential) {

        String publicKey = issuerPublicKey.getPublicKey();
        if (StringUtils.isEmpty(publicKey)) {
            return new ResponseData<Boolean>(false, ErrorCode.CREDENTIAL_PUBLIC_KEY_NOT_EXISTS);
        }
        if (isLiteCredential(credential)) {
            return verifyLiteCredential(credential, issuerPublicKey.getPublicKey());
        }
        ErrorCode errorCode = verifyContent(credential, publicKey, true);
        if (errorCode.getCode() != ErrorCode.SUCCESS.getCode()) {
            return new ResponseData<Boolean>(false, errorCode);
        }
        return new ResponseData<Boolean>(true, ErrorCode.SUCCESS);
    }

    // todo 验证由PDF Transportation传输的Presentation
    //
    @Override
    public ResponseData<Boolean> verifyPresentationFromPdf(
        String pdfTemplatePath,
        byte[] serializePdf,
        String presenterWeId,
        PresentationPolicyE presentationPolicyE,
        Challenge challenge,
        PresentationE presentationE) {

        //verify pdf
        PdfAttributeInfo pdfAttributeInfo = getPdfTransportation().getBaseData(serializePdf);
        if (pdfAttributeInfo == null) {
            logger.error("[verifyPresentationFromPDF] get pdf base data error.");
        }
        Boolean retVerifyPdf = getPdfTransportation().verifyPdf(
            presentationE,
            pdfTemplatePath,
            pdfAttributeInfo,
            serializePdf
        );

        if (!retVerifyPdf) {
            logger.error("[verifyPresentationFromPDF] verify pdf error.");
            return new ResponseData<>(false, ErrorCode.TRANSPORTATION_PDF_VERIFY_ERROR);
        }

        List<String> typeList = presentationE.getType();
        if (typeList.contains(CredentialConstant.PRESENTATION_PDF)) {
            typeList.remove(CredentialConstant.PRESENTATION_PDF);
        }
        presentationE.setType(typeList);

        return this.verify(presenterWeId, presentationPolicyE, challenge, presentationE);
    }

    private ErrorCode checkInputArgs(
        String presenterWeId,
        PresentationPolicyE presentationPolicyE,
        Challenge challenge,
        PresentationE presentationE) {

        if (StringUtils.isBlank(presenterWeId)
            || challenge == null
            || StringUtils.isBlank(challenge.getNonce())
            || !CredentialPojoUtils.checkPresentationPolicyEValid(presentationPolicyE)) {
            logger.error("[verify] presentation verify failed, please check your input.");
            return ErrorCode.ILLEGAL_INPUT;
        }

        ErrorCode errorCode = CredentialPojoUtils.checkPresentationEValid(presentationE);
        if (errorCode.getCode() != ErrorCode.SUCCESS.getCode()) {
            logger.error(
                "[verify] presentation verify failed, error message : {}",
                errorCode.getCodeDesc()
            );
            return errorCode;
        }

        //verify presenterWeId
        if (StringUtils.isNotBlank(challenge.getWeId())
            && !presenterWeId.equals(challenge.getWeId())) {
            logger.error("[verify] The input issuer weid is not match the presentian's.");
            return ErrorCode.CREDENTIAL_PRESENTERWEID_NOTMATCH;
        }

        //verify challenge
        if (!challenge.getNonce().equals(presentationE.getNonce())) {
            logger
                .error("[verify] The nonce of challenge is not matched with the presentationE's.");
            return ErrorCode.PRESENTATION_CHALLENGE_NONCE_MISMATCH;
        }

        //verify Signature of PresentationE
        WeIdDocument weIdDocument = getWeIdService().getWeIdDocument(presenterWeId).getResult();
        if (weIdDocument == null) {
            logger.error(
                "[verify]presentation verify failed, because the presenter weid :{} "
                    + "does not exist.",
                presenterWeId);
            return ErrorCode.WEID_DOES_NOT_EXIST;
        }
        String signature = presentationE.getSignature();
        errorCode =
            DataToolUtils
                .verifySignatureFromWeId(presentationE.toRawData(), signature, weIdDocument);
        if (errorCode.getCode() != ErrorCode.SUCCESS.getCode()) {
            logger.error(
                "[verify] verify presentation signature failed, error message : {}.",
                errorCode.getCodeDesc()
            );
            return ErrorCode.PRESENTATION_SIGNATURE_MISMATCH;
        }
        return ErrorCode.SUCCESS;
    }

    private ErrorCode verifyCptId(
        Map<Integer, ClaimPolicy> policyMap,
        List<CredentialPojo> credentialList) {

        if (policyMap.size() > credentialList.size()) {
            return ErrorCode.CREDENTIAL_CPTID_NOTMATCH;
        } else {
            for (CredentialPojo credential : credentialList) {
                if (isZkpCredential(credential)) {
                    continue;
                } else {
                    Integer cptId = credential.getCptId();
                    if (cptId == null || !policyMap.containsKey(cptId)) {
                        return ErrorCode.CREDENTIAL_CPTID_NOTMATCH;
                    }
                }
            }
        }
        return ErrorCode.SUCCESS;
    }

    private ErrorCode verifyDisclosureAndSalt(
        Map<String, Object> disclosureMap,
        Map<String, Object> saltMap) {

        for (String disclosureK : disclosureMap.keySet()) {
            Object disclosureV = disclosureMap.get(disclosureK);
            Object saltV = saltMap.get(disclosureK);
            if (disclosureV instanceof Map) {
                ErrorCode code = verifyDisclosureAndSalt((HashMap) disclosureV, (HashMap) saltV);
                if (code.getCode() != ErrorCode.SUCCESS.getCode()) {
                    return code;
                }
            } else if (disclosureV instanceof List) {
                ArrayList<Object> disclosurs = (ArrayList<Object>) disclosureV;
                ErrorCode code = verifyDisclosureAndSaltList(disclosurs, (ArrayList<Object>) saltV);
                if (code.getCode() != ErrorCode.SUCCESS.getCode()) {
                    return code;
                }
            } else {
                String disclosure = String.valueOf(disclosureV);

                if (saltV == null
                    || (!disclosure.equals(NOT_DISCLOSED) && !disclosure.equals(DISCLOSED)
                    && !disclosure.equals(EXISTED))) {
                    logger.error(
                        "[verifyDisclosureAndSalt] policy disclosureValue {} illegal.",
                        disclosureMap
                    );
                    return ErrorCode.CREDENTIAL_POLICY_DISCLOSUREVALUE_ILLEGAL;
                }

                String salt = String.valueOf(saltV);
                if ((disclosure.equals(NOT_DISCLOSED) && salt.length() > 1)
                    || (disclosure.equals(NOT_DISCLOSED) && !salt.equals(NOT_DISCLOSED))) {
                    return ErrorCode.CREDENTIAL_DISCLOSUREVALUE_NOTMATCH_SALTVALUE;
                }

                if (disclosure.equals(DISCLOSED) && salt.length() <= 1) {
                    return ErrorCode.CREDENTIAL_DISCLOSUREVALUE_NOTMATCH_SALTVALUE;
                }
            }
        }
        return ErrorCode.SUCCESS;
    }

    private ErrorCode verifyDisclosureAndSaltList(
        List<Object> disclosureList,
        List<Object> saltList
    ) {
        for (int i = 0; i < disclosureList.size(); i++) {
            Object disclosure = disclosureList.get(i);
            Object saltV = saltList.get(i);
            if (disclosure instanceof Map) {
                ErrorCode code =
                    verifyDisclosureAndSaltList(
                        (HashMap) disclosure,
                        (ArrayList<Object>) saltList
                    );
                if (code.getCode() != ErrorCode.SUCCESS.getCode()) {
                    return code;
                }
            } else if (disclosure instanceof List) {
                ErrorCode code =
                    verifyDisclosureAndSaltList(
                        (ArrayList<Object>) disclosure,
                        (ArrayList<Object>) saltV
                    );
                if (code.getCode() != ErrorCode.SUCCESS.getCode()) {
                    return code;
                }
            }
        }
        return ErrorCode.SUCCESS;
    }

    private ErrorCode verifyDisclosureAndSaltList(
        Map<String, Object> disclosure,
        List<Object> saltList
    ) {
        for (int i = 0; i < saltList.size(); i++) {
            Object saltV = saltList.get(i);
            ErrorCode code = verifyDisclosureAndSalt((HashMap) disclosure, (HashMap) saltV);
            if (code.getCode() != ErrorCode.SUCCESS.getCode()) {
                return code;
            }
        }
        return ErrorCode.SUCCESS;
    }

    private ErrorCode verifyPolicy(CredentialPojo credentialPojo, ClaimPolicy claimPolicy,
        String presenterWeId) {
        if (isZkpCredential(credentialPojo)) {
            return ErrorCode.SUCCESS;
        }
        Map<String, Object> saltMap = credentialPojo.getSalt();
        String disclosure = claimPolicy.getFieldsToBeDisclosed();
        Map<String, Object> disclosureMap = DataToolUtils.deserialize(disclosure, HashMap.class);

        Object idValue = disclosureMap.get("id");
        if (idValue != null) {
            Object weid = credentialPojo.getClaim().get("id");
            if (StringUtils.equals(String.valueOf(idValue), DISCLOSED)) {
                if (!StringUtils.equals(String.valueOf(weid), presenterWeId)) {
                    logger.error(
                        "[verifyPolicy] the presenter weid->{} of presentation does not "
                            + "match the credential's ->{}. ",
                        presenterWeId,
                        weid);
                    return ErrorCode.PRESENTATION_WEID_CREDENTIAL_WEID_MISMATCH;
                }
            } else if (StringUtils.equals(String.valueOf(idValue), EXISTED)
                && !credentialPojo.getClaim().containsKey("id")) {
                logger.error(
                    "[verifyPolicy] the presenter weid->{} of presentation does not "
                        + "match the credential's ->{}. ",
                    presenterWeId,
                    weid);
                return ErrorCode.PRESENTATION_CREDENTIAL_CLAIM_WEID_NOT_EXIST;
            }
        }
        return this.verifyDisclosureAndSalt(disclosureMap, saltMap);
    }

    /**
     * TODO 【超级重要】
     * TODO 创建一个 Presentation 实例
     * @param credentialList original credential list
     * @param presentationPolicyE the disclosure strategies.
     * @param challenge used for authentication
     * @param weIdAuthentication owner information
     * @return
     */
    @Override
    public ResponseData<PresentationE> createPresentation(
        List<CredentialPojo> credentialList,                    // 需要组装成 Presentation 的Credential List
        PresentationPolicyE presentationPolicyE,                // 各个Credential对应的Claim 选择性披露 或者 零知识证明的 Policy
        Challenge challenge,                                    // 当前 Presentation 的验证方给 holder 的 Challenge
        WeIdAuthentication weIdAuthentication) {                // 生成当前 Presentation 的holder 的 Authentication

        // 构造一个 空的 Presentation
        PresentationE presentation = new PresentationE();
        try {
            // 检查输入数据完整性
            ErrorCode errorCode =
                validateCreateArgs(
                    credentialList,             // Credential List
                    presentationPolicyE,        // Presentation的Policy
                    challenge,
                    weIdAuthentication
                );
            if (errorCode.getCode() != ErrorCode.SUCCESS.getCode()) {
                logger.error(
                    "check input error:{}-{}",
                    errorCode.getCode(),
                    errorCode.getCodeDesc()
                );
                return new ResponseData<PresentationE>(null, errorCode);
            }
            // todo 处理 credential List数据, 取回精处理后的 具备选择性披露的 Credential 的List,
            //      回填到 presentation 中
            errorCode = processCredentialList(
                    credentialList,
                    presentationPolicyE,
                    presentation,               // 这个是要 回填的 presentation
                weIdAuthentication.getWeId());
            if (errorCode.getCode() != ErrorCode.SUCCESS.getCode()) {
                logger.error(
                    "process credentialList error:{}-{}",
                    errorCode.getCode(),
                    errorCode.getCodeDesc()
                );
                return new ResponseData<PresentationE>(null, errorCode);
            }

            // 给 Presentation 实例填充 @context 的内容
            presentation.getContext().add(CredentialConstant.DEFAULT_CREDENTIAL_CONTEXT);
            // 给 Presentation 实例填充 type 的内容
            presentation.getType().add(WeIdConstant.DEFAULT_PRESENTATION_TYPE);

            // 处理proof数据
            //
            // todo challenge 挑战 是在这里用的
            generatePresentationProof(challenge, weIdAuthentication, presentation);
            return new ResponseData<PresentationE>(presentation, ErrorCode.SUCCESS);
        } catch (Exception e) {
            logger.error("create PresentationE error", e);
            return new ResponseData<PresentationE>(null, ErrorCode.UNKNOW_ERROR);
        }
    }

    // todo 校验 创建 Presentation 的入参
    private ErrorCode validateCreateArgs(
        List<CredentialPojo> credentialList,
        PresentationPolicyE presentationPolicyE,
        Challenge challenge,
        WeIdAuthentication weIdAuthentication) {

        if (challenge == null || weIdAuthentication == null) {
            return ErrorCode.ILLEGAL_INPUT;
        }
        if (StringUtils.isBlank(challenge.getNonce())
            || challenge.getVersion() == null) {
            return ErrorCode.PRESENTATION_CHALLENGE_INVALID;
        }
        if (weIdAuthentication.getWeIdPrivateKey() == null
            || !WeIdUtils.validatePrivateKeyWeIdMatches(
            weIdAuthentication.getWeIdPrivateKey(), weIdAuthentication.getWeId())) {
            return ErrorCode.WEID_PRIVATEKEY_DOES_NOT_MATCH;
        }
        if (!StringUtils.isBlank(challenge.getWeId())
            && !challenge.getWeId().equals(weIdAuthentication.getWeId())) {
            return ErrorCode.PRESENTATION_CHALLENGE_WEID_MISMATCH;
        }
        if (StringUtils.isBlank(weIdAuthentication.getWeIdPublicKeyId())) {
            return ErrorCode.PRESENTATION_WEID_PUBLICKEY_ID_INVALID;
        }


        // 上面都是一些 形式检验
        // todo 这里才是 根据  presentation 的 policy 校验 Credential List中的 Credential
        return validateClaimPolicy(credentialList, presentationPolicyE);
    }

    // todo 根据  presentation 的 policy 校验 Credential List中的 Credential
    private ErrorCode validateClaimPolicy(
        List<CredentialPojo> credentialList,
        PresentationPolicyE presentationPolicyE) {
        if (CollectionUtils.isEmpty(credentialList)) {
            return ErrorCode.ILLEGAL_INPUT;
        }
        if (presentationPolicyE == null || presentationPolicyE.getPolicy() == null) {
            return ErrorCode.PRESENTATION_POLICY_INVALID;
        }
        if (!WeIdUtils.isWeIdValid(presentationPolicyE.getPolicyPublisherWeId())) {
            return ErrorCode.PRESENTATION_POLICY_PUBLISHER_WEID_INVALID;
        }
        ResponseData<Boolean> weIdRes = getWeIdService()
            .isWeIdExist(presentationPolicyE.getPolicyPublisherWeId());
        if (ErrorCode.SUCCESS.getCode() != weIdRes.getErrorCode() || !weIdRes.getResult()) {
            return ErrorCode.PRESENTATION_POLICY_PUBLISHER_WEID_NOT_EXIST;
        }

        // todo 逐个校验 Credential 是否可用
        for (CredentialPojo credentialPojo : credentialList) {
            ErrorCode checkResp = CredentialPojoUtils.isCredentialPojoValid(credentialPojo);
            if (ErrorCode.SUCCESS.getCode() != checkResp.getCode()) {
                return checkResp;
            }
        }

        // todo 收集出 所有的Credential信息中的 cptId
        List<Integer> cptIdList = credentialList.stream().map(
            cpwl -> cpwl.getCptId()).collect(Collectors.toList());

        // todo 收集出 Policy 中的 cptId
        Set<Integer> claimPolicyCptSet = presentationPolicyE.getPolicy().keySet();

        // TODO 比较 双方的 cptId 是否匹配
        if (!cptIdList.containsAll(claimPolicyCptSet)) {
            return ErrorCode.PRESENTATION_CREDENTIALLIST_MISMATCH_CLAIM_POLICY;
        }
        return ErrorCode.SUCCESS;
    }

    // 处理credentialList数据, 给 presentation 实例的 `verifiableCredential` 字段回填值
    private ErrorCode processCredentialList(
        List<CredentialPojo> credentialList,
        PresentationPolicyE presentationPolicy,
        PresentationE presentation,
        String userId) {     // 当前 holder 的 WeId

        // todo 构建一个 需要对外展示的CredentialPojo List
        List<CredentialPojo> newCredentialList = new ArrayList<>();
        // 获取 Presentation的Policy中的  ClaimPolicyMap
        Map<Integer, ClaimPolicy> claimPolicyMap = presentationPolicy.getPolicy();

        // 获取 构建 Presentation 的policy类型 {ORIGINAL, ZKP}
        String policyType = presentationPolicy.getPolicyType();

        // todo 如果是 ZKP 类型的 Policy
        if (StringUtils.equals(policyType, CredentialType.ZKP.getName())) {

            // todo 将入参的 Credential List 生成零知识证明相关的 Credential List信息
            newCredentialList = generateZkpCredentialList(credentialList, presentationPolicy,
                userId);
        }

        // todo 否则是  ORIGINAL 类型的 Policy
        else {

            // todo 遍历所有原始证书
            for (CredentialPojo credential : credentialList) {
                // 根据原始证书获取对应的 claimPolicy todo (这里头装着 Claim 需要披露的字段名)
                ClaimPolicy claimPolicy = claimPolicyMap.get(credential.getCptId());
                if (claimPolicy == null) {
                    continue;
                }
                // 根据原始证书和claimPolicy去创建 选择性披露凭证
                // todo 生成选择性披露的 Credential
                //
                // todo 这里面做的几件事,
                //          一、对原始的 credential 做了一次 深拷贝出一个 credentialClone
                //          二、对 credentialClone 中的 非披露字段 做了取了 credentialClone.proof.salt 中的相应的 salt 做了Hash
                //          三、对 credentialClone中 使用过后的 salt 进行清空
                // 最后返回 credentialClone
                ResponseData<CredentialPojo> res =
                    this.createSelectiveCredential(credential, claimPolicy);
                if (res.getErrorCode().intValue() != ErrorCode.SUCCESS.getCode()) {
                    return ErrorCode.getTypeByErrorCode(res.getErrorCode().intValue());
                }

                // 收集 credentialClone
                newCredentialList.add(res.getResult());
            }
        }

        // 给 presentation  设置 新的 Credential List
        presentation.setVerifiableCredential(newCredentialList);
        return ErrorCode.SUCCESS;
    }


    // todo 用于在 生成 Presentation 时的 Credential List 中的 zkp 相关 Credential
    private List<CredentialPojo> generateZkpCredentialList(
        List<CredentialPojo> credentialList,
        PresentationPolicyE presentationPolicy,
        String userId) {

        List<CredentialPojo> newCredentialList = new ArrayList<>();
        // 获取ClaimPolicyMap
        Map<Integer, ClaimPolicy> claimPolicyMap = presentationPolicy.getPolicy();
        for (CredentialPojo credential : credentialList) {
            // 根据原始证书获取对应的 claimPolicy
            ClaimPolicy claimPolicy = claimPolicyMap.get(credential.getCptId());
            if (claimPolicy == null) {
                continue;
            }
            // todo 根据原始证书和claimPolicy去创建选择性披露凭证
            ResponseData<CredentialPojo> res = this
                .createZkpCredential(credential, claimPolicy, userId);

            if (res.getErrorCode().intValue() != ErrorCode.SUCCESS.getCode()) {
                return null;
            }
            newCredentialList.add(res.getResult());
        }

        return newCredentialList;
    }

    // 生成一个Presentation 的Proof
    private void generatePresentationProof(
        Challenge challenge,      // 用来指定需要签名时用的 nonce
        WeIdAuthentication weIdAuthentication,
        PresentationE presentation) {

        // 固定的 Proof 的生成算法, 使用 ECDSA
        String proofType = CredentialProofType.ECDSA.getTypeName();
        // 给 Presentation 设置 Proof Type (ECDSA)
        presentation.putProofValue(ParamKeyConstant.PROOF_TYPE, proofType);

        // 设置当前生成时间
        Long proofCreated = DateUtils.getNoMillisecondTimeStamp();
        presentation.putProofValue(ParamKeyConstant.PROOF_CREATED, proofCreated);

        // 设置当前 生成 Presentation 的WeId
        String weIdPublicKeyId = weIdAuthentication.getWeIdPublicKeyId();
        // 设置当前 生成 Presentation 的verificationMethod
        presentation.putProofValue(ParamKeyConstant.PROOF_VERIFICATION_METHOD, weIdPublicKeyId);
        // 设置当前 生成 Presentation 的nonce todo 使用挑战中给定的 nonce
        presentation.putProofValue(ParamKeyConstant.PROOF_NONCE, challenge.getNonce());

        // 使用 当前 WeId 对应的 私钥对 presentation 的进行 签名
        String signature =
            DataToolUtils.sign(
                // presentation 序列化之后的 data
                presentation.toRawData(),
                // 生成当前 presentation 的 weId 的 privateKey
                weIdAuthentication.getWeIdPrivateKey().getPrivateKey()
            );
        // 设置当前 生成 Presentation 的signatureValue
        presentation.putProofValue(ParamKeyConstant.PROOF_SIGNATURE, signature);
    }

    /**
     * TODO 使用第 三方可信时间戳 服务，创建一个可信时间戳凭证
     *
     *
     * TODO 注意: 本服务需要您先行配置好时间戳服务的相关参数，请参见时间戳服务配置步骤.
     *      当前，可信时间戳服务支持使用 WeSign（微鉴证）集成.
     *
     *
     * TODO 注意: 创建可信时间戳凭证的输入参数是一个 凭证 list。 (Credential List)
     *      当前，因为一些技术限制，还不支持对 **已经选择性披露的凭证** 进行可信时间戳的创建。
     *      也就是说，如果您传入的 凭证list里面有任何一个凭证是选择性披露的，那么创建将会失败.
     *
     *
     * TODO 注意: 对于已经创建好的可信时间戳凭证，您可以通过调用 createSelectiveCredential 对其进行选择性披露.
     *
     * Create a trusted timestamp credential.
     *
     *
     * {
     *      "claim": {
     *        "credentialList": [
     *          {
     *            "claim": {
     *              "age": 1,
     *              "gender": "F",
     *              "id": "did:weid:1000:1:0xa4c2666560499868baf1906941f806b6d1c26e33",
     *              "name": "1"
     *            },
     *            "context": "https:\/\/github.com\/WeBankFinTech\/WeIdentity\/blob\/master\/context\/v1",
     *            "cptId": 2000087,
     *            "expirationDate": 1567491752,
     *            "id": "6ea6e209-10e9-4a93-b6be-12af1a32655b",
     *            "issuanceDate": 1567405352,
     *            "issuer": "did:weid:1000:1:0xa4c2666560499868baf1906941f806b6d1c26e33",
     *            "proof": {
     *              "created": 1567405352,
     *              "creator": "did:weid:1000:1:0xa4c2666560499868baf1906941f806b6d1c26e33#keys-0",
     *              "salt": {
     *                "age": "yOwN7",
     *                "gender": "jjB85",
     *                "id": "BmRYI",
     *                "name": "BjYqF"
     *              },
     *              "signatureValue": "G+SNG3rBZNDvRNgRtJugPtX1FmE8XJIkV4CGPK\/nt\/breIPMJ5wYxImTp2QAxBUe5HMwCe9PPGhhMJJAazM5u9k=",
     *              "type": "Secp256k1"
     *            },
     *            "type": [
     *              "VerifiableCredential"
     *            ]
     *          },
     *          {
     *            "claim": {
     *              "age": 1,
     *              "gender": "F",
     *              "id": "did:weid:1000:1:0x309320a01f215a380c6950e80a89181ad8a8cd53",
     *              "name": "1"
     *            },
     *            "context": "https:\/\/github.com\/WeBankFinTech\/WeIdentity\/blob\/master\/context\/v1",
     *            "cptId": 2000087,
     *            "expirationDate": 1567491842,
     *            "id": "a3544a9c-6cb6-4688-9622-bb935fb0d93f",
     *            "issuanceDate": 1567405355,
     *            "issuer": "did:weid:1000:1:0x309320a01f215a380c6950e80a89181ad8a8cd53",
     *            "proof": {
     *              "created": 1567405355,
     *              "creator": "did:weid:1000:1:0x309320a01f215a380c6950e80a89181ad8a8cd53#keys-0",
     *              "salt": {
     *                "age": "5nImi",
     *                "gender": "Me224",
     *                "id": "5pYs2",
     *                "name": "z6VmW"
     *              },
     *              "signatureValue": "HC8OAG\/dRmteGSIGWIDekp8fC1KJI8EEDZBb29HiTLXvVj350l9yTOHeGSBCr2VRY\/DSHT5ONjlvcrO4Mqa3Auo=",
     *              "type": "Secp256k1"
     *            },
     *            "type": [
     *              "VerifiableCredential"
     *            ]
     *          }
     *        ],
     *      "timestampAuthority": "wesign",
     *      "authoritySignature": "MhmbHC1y3rfyb\/2sg+E2Uulczm8VDtmQ6VrU\/9ow4e4nP3lVUOv4Gz41pfBrJHnV4wQoUbQsCYpezFx5sdaUwUILV1I=HC1y3rfyb\/2sg+E2Uulczm8VDtmQ6VrU\/9ow4e4nP3lVUOv4Gz41pfBrJHnV4wQoUbQsCYpezFx5sdaUwUILV1I=HC1y3rfyb\/2sg+E2Uulczm8VDtmQ6VrU\/9ow4e4nP3lVUOv4Gz41pfBrJHnV4wQoUbQsCYpezFx5sdaUwUILV1I=a235==",
     *      "timestamp": 151233113000,
     *      "claimHash": "0xe3f48648beee61d17de609d32af36ac0bf4d68a9352890b04d53841c4949bd13"
     *      },
     *      "context": "https:\/\/github.com\/WeBankFinTech\/WeIdentity\/blob\/master\/context\/v1",
     *      "cptId": 108,
     *      "expirationDate": 1567491842,
     *      "id": "ad5d5a54-4574-4b3b-b1df-9d0687b6a0ac",
     *      "issuanceDate": 1567405359,
     *      "issuer": "did:weid:1000:1:0x4e9a111867ed6370e1e23f7a79426f6649eb78c6",
     *      "proof": {
     *        "created": 1567405359,
     *        "creator": "did:weid:1000:1:0x4e9a111867ed6370e1e23f7a79426f6649eb78c6#keys-0",
     *        "salt": {
     *          "credentialList": ""
     *        },
     *        "signatureValue": "HC1y3rfyb\/2sg+E2Uulczm8VDtmQ6VrU\/9ow4e4nP3lVUOv4Gz41pfBrJHnV4wQoUbQsCYpezFx5sdaUwUILV1I=",
     *        "type": "Secp256k1"
     *      },
     *      "type": [
     *        "VerifiableCredential"
     *      ]
     *    }
     *
     * TODO 可信时间 凭证 是一个, 【对某个 Credential 生成全部不披露的凭证并生成hash, 然后根据Hash 和时间戳再生成的一个 Credential ??】
     * @param credentialList the credentialPojo list to be signed
     * @param weIdAuthentication the caller authentication
     * @return the embedded timestamp in credentialPojo
     */
    @Override
    public ResponseData<CredentialPojo> createTrustedTimestamp(
        List<CredentialPojo> credentialList,
        WeIdAuthentication weIdAuthentication) {
        if (credentialList == null || credentialList.size() == 0
            || CredentialPojoUtils.isWeIdAuthenticationValid(weIdAuthentication)
            != ErrorCode.SUCCESS) {
            return new ResponseData<>(null, ErrorCode.ILLEGAL_INPUT);
        }

        // For business reasons, we do not allow a selectively disclosed credential to be stamped.
        if (CredentialPojoUtils.isSelectivelyDisclosedCredentialList(credentialList)) {
            return new ResponseData<>(null,
                ErrorCode.TIMESTAMP_CREATION_FAILED_FOR_SELECTIVELY_DISCLOSED);
        }

        CredentialPojo credential = new CredentialPojo();
        credential.setCptId(CredentialConstant.EMBEDDED_TIMESTAMP_CPT);
        String privateKey = weIdAuthentication.getWeIdPrivateKey().getPrivateKey();
        ECKeyPair keyPair = ECKeyPair.create(new BigInteger(privateKey));
        String keyWeId = WeIdUtils
            .convertAddressToWeId(new Address(Keys.getAddress(keyPair)).toString());
        credential.setIssuer(keyWeId);
        credential.setIssuanceDate(DateUtils.getNoMillisecondTimeStamp());
        credential.setId(UUID.randomUUID().toString());
        credential.setContext(CredentialUtils.getDefaultCredentialContext());
        // WeSign default valid: 1 year
        credential.setExpirationDate(DateUtils.getNoMillisecondTimeStamp() + 31536000L);
        credential.addType(CredentialConstant.DEFAULT_CREDENTIAL_TYPE);

        String rawData = CredentialPojoUtils
            .getEmbeddedCredentialThumbprintWithoutSig(credentialList);
        ResponseData<HashMap<String, Object>> claimResp = TimestampUtils
            .createWeSignTimestamp(rawData);
        if (claimResp.getResult() == null) {
            return new ResponseData<>(null, claimResp.getErrorCode(), claimResp.getErrorMessage());
        }
        HashMap<String, Object> claim = claimResp.getResult();
        List<Map> trimmedCredentialMapList = trimCredentialList(credentialList);
        claim.put("credentialList", trimmedCredentialMapList);
        credential.setClaim(claim);

        // For embedded signature, salt here is totally meaningless - hence we left it blank
        Map<String, Object> saltMap = DataToolUtils.clone(claim);
        CredentialPojoUtils.clearMap(saltMap);
        String signature = DataToolUtils.sign(rawData, privateKey);

        credential.putProofValue(ParamKeyConstant.PROOF_CREATED, credential.getIssuanceDate());

        String weIdPublicKeyId = weIdAuthentication.getWeIdPublicKeyId();
        credential.putProofValue(ParamKeyConstant.PROOF_CREATOR, weIdPublicKeyId);

        String proofType = CredentialProofType.ECDSA.getTypeName();
        credential.putProofValue(ParamKeyConstant.PROOF_TYPE, proofType);
        credential.putProofValue(ParamKeyConstant.PROOF_SIGNATURE, signature);
        credential.setSalt(saltMap);

        return new ResponseData<>(credential, ErrorCode.SUCCESS);
    }

    // todo 此接口仅在使用 `WeDPR` 的选择性披露时才需要调用，用于生成一些中间数据。
    //      用户根据传入的preCredential，
    //      claimJson以及weIdAuthentication生成基于系统CPT 111的credential。
    //
    // todo 最终由 AmopService 调用, 生成 zkp 相关的 Credential
    /* (non-Javadoc)
     * @see com.webank.weid.rpc.CredentialPojoService#prepareZKPCredential(
     * com.webank.weid.protocol.base.CredentialPojo, java.lang.Object)
     */
    @Override
    public ResponseData<CredentialPojo> prepareZkpCredential(
        CredentialPojo preCredential,           // 还未形成 Credential 的一些预热信息
        String claimJson,                       // (用户填入的 Claim) 入参的 用来生成 Credential 的Claim 部分 (不是最终的Claim, 里面有些字段需要放到外面的Credential 中)
        WeIdAuthentication weIdAuthentication   // 认证方式, 该类只有三个字段   WeId/PubKey/PriKey
    ) {

        //1. verify pre-credential.
        //
        // 校验 Pre-Credential 信息
        ResponseData<Boolean> verifyResult = this.verify(preCredential.getIssuer(), preCredential);
        if (verifyResult.getErrorCode().intValue() != ErrorCode.SUCCESS.getCode()) {
            logger.error("[prepareZKPCredential] pre-credential verified failed.");
            return new ResponseData<CredentialPojo>(null,
                ErrorCode.getTypeByErrorCode(verifyResult.getErrorCode()));
        }

        //2.build credentialInfoMap and make credential.
        //
        // 提取出 Pre-Credential 的 Claim 中的 cptId
        Integer cptId = (Integer) preCredential.getClaim()
            .get(CredentialConstant.CREDENTIAL_META_KEY_CPTID);

        // todo 构建 Credential 实例,  这里会和 chain 操作, 也会和远端第三方请求操作
        UserResult userResult = makeCredential(preCredential, claimJson, cptId, weIdAuthentication);

        //3. generate credential based on CPT 111 and userResult.
        //
        // 根据CPT 111和userResult生成凭据。 todo 这里用到了 随机 salt
        return generateCpt111Credential(weIdAuthentication, cptId, userResult);
    }

    /**
     * todo 根据CPT 111和userResult生成凭据。
     * generate credential based on cpt 111.
     *
     * @param weIdAuthentication auth
     * @param cptId cpt id
     * @param userResult userResult made by user
     * @return credential signed by user.
     */
    private ResponseData<CredentialPojo> generateCpt111Credential(
        WeIdAuthentication weIdAuthentication,
        Integer cptId,
        UserResult userResult) {

        Cpt111 cpt111 = new Cpt111();
        cpt111.setCptId(String.valueOf(cptId));
        cpt111.setCredentialSignatureRequest(userResult.credentialSignatureRequest);
        cpt111.setUserNonce(userResult.userNonce);
        CreateCredentialPojoArgs args = new CreateCredentialPojoArgs();
        args.setClaim(cpt111);
        args.setWeIdAuthentication(weIdAuthentication);

        // cpt 111 是 零知识证明的 CPT 啊
        args.setCptId(CredentialConstant.ZKP_USER_NONCE_CPT);
        args.setIssuer(weIdAuthentication.getWeId());
        //args.setId(preCredential.getId());
        args.setIssuanceDate(System.currentTimeMillis());
        args.setExpirationDate(System.currentTimeMillis() + 24 * 60 * 60 * 1000);

        // todo  来了来了, 生成真正的 Credential 了
        //
        // todo 依赖外部入参 构造 Credential
        return this.createCredential(args); // 生成 cpt111 的Credential
    }

    // todo 用于在 生成 Presentation 时的 Credential List 中的 zkp 相关 Credential
    private ResponseData<CredentialPojo> createZkpCredential(
        CredentialPojo credential,
        ClaimPolicy claimPolicy,
        String userId) {   // holder 的weId
        try {
            CredentialPojo credentialClone = DataToolUtils.clone(credential);
            ErrorCode checkResp = CredentialPojoUtils.isCredentialPojoValid(credentialClone);
            if (ErrorCode.SUCCESS.getCode() != checkResp.getCode()) {
                return new ResponseData<CredentialPojo>(null, checkResp);
            }
            if (credentialClone.getCptId()
                .equals(CredentialConstant.CREDENTIALPOJO_EMBEDDED_SIGNATURE_CPT)) {
                return new ResponseData<>(null, ErrorCode.CPT_ID_ILLEGAL);
            }
            if (claimPolicy == null) {
                logger.error("[createZkpCredential] claimPolicy is null.");
                return new ResponseData<CredentialPojo>(null,
                    ErrorCode.CREDENTIAL_CLAIM_POLICY_NOT_EXIST);
            }
            List<String> revealedAttributeList = new ArrayList<>();  // 显露 列表
            List<Predicate> predicateList = new ArrayList<>();       // 谓语 列表

            // TODO 零知识证明 相关 Credential
            //
            //
            processZkpPolicy(claimPolicy, revealedAttributeList, predicateList);


            // 和WDR 相关 SDK 封装的东西了
            VerificationRule verificationRule =
                VerificationRule.newBuilder()
                    .addAllRevealedAttribute(revealedAttributeList)
                    .addAllPredicateAttribute(predicateList)
                    .build();


            String encodedVerificationRule = Utils.protoToEncodedString(verificationRule);
            ResponseData<String> dbResp =
                getDataDriver().get(
                    DataDriverConstant.DOMAIN_USER_CREDENTIAL_SIGNATURE,
                    credential.getId());
            Integer cptId = credentialClone.getCptId();
            String id = new StringBuffer().append(userId).append("_").append(cptId).toString();
            String newCredentialSignature = dbResp.getResult();
            ResponseData<String> masterKeyResp =
                getDataDriver().get(
                    DataDriverConstant.DOMAIN_USER_MASTER_SECRET,
                    id);

            HashMap<String, String> userCredentialInfo = DataToolUtils
                .deserialize(masterKeyResp.getResult(), HashMap.class);
            String masterSecret = userCredentialInfo.get("masterSecret");

            ResponseData<CredentialTemplateEntity> credentialTemplateResp = getCptService()
                .queryCredentialTemplate(cptId);


            CredentialTemplateEntity credentialTemplate = credentialTemplateResp.getResult();
            Map<String, String> credentialInfoMap = new HashMap<>();
            credentialInfoMap = JsonUtil.credentialToMonolayer(credential);
            UserResult userResult =
                UserClient.proveCredentialInfo(
                    encodedVerificationRule,
                    newCredentialSignature, //from db
                    credentialInfoMap,  //from credential
                    credentialTemplate, //from blockchain and cpt
                    masterSecret); //from db

            String verificationRequest = userResult.verificationRequest;

            porcessZkpDisclosedValue(credentialClone, claimPolicy);
            //CredentialPojo zkpCredential = new CredentialPojo();
            credentialClone.setProof(null);
            credentialClone
                .putProofValue(ParamKeyConstant.PROOF_VERIFICATIONREQUEST, verificationRequest);
            credentialClone.putProofValue(ParamKeyConstant.PROOF_ENCODEDVERIFICATIONRULE,
                encodedVerificationRule);
            List<String> zkpTyps = new ArrayList<>();
            zkpTyps.add(CredentialConstant.DEFAULT_CREDENTIAL_TYPE);
            zkpTyps.add(CredentialType.ZKP.getName());
            credentialClone.setType(zkpTyps);
            return new ResponseData<CredentialPojo>(credentialClone, ErrorCode.SUCCESS);
        } catch (DataTypeCastException e) {
            logger.error("Generate SelectiveCredential failed, "
                + "credential disclosure data type illegal. ", e);
            return new ResponseData<>(null, ErrorCode.CREDENTIAL_DISCLOSURE_DATA_TYPE_ILLEGAL);
        } catch (WeIdBaseException e) {
            logger.error("Generate SelectiveCredential failed, "
                + "policy disclosurevalue illegal. ", e);
            return new ResponseData<>(null, ErrorCode.CREDENTIAL_POLICY_DISCLOSUREVALUE_ILLEGAL);
        } catch (Exception e) {
            logger.error("Generate SelectiveCredential failed due to system error. ", e);
            return new ResponseData<>(null, ErrorCode.CREDENTIAL_ERROR);
        }

    }

    private void porcessZkpDisclosedValue(CredentialPojo credential, ClaimPolicy claimPolicy) {

        String disclosure = claimPolicy.getFieldsToBeDisclosed();
        Map<String, Object> saltMap = credential.getSalt();
        Map<String, Object> claim = credential.getClaim();

        Map<String, Object> disclosureMap = DataToolUtils
            .deserialize(disclosure, HashMap.class);

        Map<String, Object> claimDisclosureMap = (Map<String, Object>) disclosureMap.get("claim");
        if (claimDisclosureMap == null || !(claimDisclosureMap instanceof Map)) {
            return;
        }
        // 补 policy
        addKeyToPolicy(claimDisclosureMap, claim);
        // 加盐处理
        addSelectSalt(claimDisclosureMap, saltMap, claim, true);

        disclosureMap.remove("claim");
        processMetaDisclosedValue(credential, disclosureMap);

    }

    private void processMetaDisclosedValue(CredentialPojo credential,
        Map<String, Object> disclosureMap) {

        for (Map.Entry<String, Object> entry : disclosureMap.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();
            String salt = DataToolUtils.getRandomSalt();
            if ((value instanceof Map) || !StringUtils.equals(String.valueOf(value), DISCLOSED)) {
                switch (key) {
                    case CredentialConstant.ID:
                        credential
                            .setId(CredentialPojoUtils.getFieldSaltHash(credential.getId(), salt));
                        break;
                    case CredentialConstant.CREDENTIAL_META_KEY_ISSUANCEDATE:
                        credential.setIssuanceDate(0L);
                        break;
                    case CredentialConstant.CREDENTIAL_META_KEY_EXPIRATIONDATE:
                        credential.setExpirationDate(0L);
                        break;
                    case CredentialConstant.CREDENTIAL_META_KEY_CPTID:
                        credential.setCptId(0);
                        break;
                    case CredentialConstant.CREDENTIAL_META_KEY_ISSUER:
                        credential.setIssuer(
                            CredentialPojoUtils.getFieldSaltHash(credential.getIssuer(), salt));
                        break;
                    case CredentialConstant.CREDENTIAL_META_KEY_CONTEXT:
                        credential.setIssuer(
                            CredentialPojoUtils.getFieldSaltHash(credential.getContext(), salt));
                        break;
                    default:
                        break;
                }
            }
        }
    }

    // TODO 根据传入的 授权要求信息，生成符合 CPT101 格式规范的【数据授权凭证】。
    //      该凭证需要被 verify之后 和 Endpoint Service结合使用.
    //
    //
    // TODO 注意：使用这个接口的前提是首先需要将CPT 101注册到链上。
    //      如果您是新搭了一条WeIdentity 1.6.0+的链，那么搭链过程中这一步已经自动完成了。
    //      否则（如您是升级SDK），您需要使用部署WeIdentity合约的私钥（ecdsa_key）去将CPT 101注册到链上。
    //      下文的代码范例中我们给出了详细的流程.
    //
    //
    // {
    //        "claim": {
    //            "duration": 360000,
    //            "fromWeId": "did:weid:101:0x69cd071e4be5fd878e1519ff476563dc2f4c6168",
    //            "resourceId": "4b077c17-9612-42ee-9e36-3a3d46b27e81",
    //            "serviceUrl": "http://127.0.0.1:6010/fetch-data",
    //            "toWeId": "did:weid:101:0x68bedb2cbe55b4c8e3473faa63f121c278f6dba9"
    //        },
    //        "context": "https://github.com/WeBankFinTech/WeIdentity/blob/master/context/v1",
    //        "cptId": 101,
    //        "expirationDate": 1581347039,
    //        "id": "48b75424-9411-4d22-b925-4e730b445a31",
    //        "issuanceDate": 1580987039,
    //        "issuer": "did:weid:101:0x69cd071e4be5fd878e1519ff476563dc2f4c6168",
    //        "proof": {
    //            "created": 1580987039,
    //            "creator": "did:weid:101:0x69cd071e4be5fd878e1519ff476563dc2f4c6168#keys-0",
    //            "salt": {
    //                "duration": "fmk5A",
    //                "fromWeId": "DEvFy",
    //                "resourceId": "ugVeN",
    //                "serviceUrl": "nVdeE",
    //                "toWeId": "93Z1E"
    //            },
    //            "signatureValue": "HCZwyTzGst87cjCDaUEzPrO8QRlsPvCYXvRTUVBUTDKRSoGDgu4h4HLrMZ+emDacRnmQ/yke38u1jBnilNnCh6c=",
    //            "type": "Secp256k1"
    //        },
    //        "type": ["VerifiableCredential", "hashTree"]
    //    }
    //
    /* (non-Javadoc)
     * @see com.webank.weid.rpc.CredentialPojoService#createDataAuthToken()
     */
    @Override
    public ResponseData<CredentialPojo> createDataAuthToken(
        Cpt101 authInfo,
        WeIdAuthentication weIdAuthentication) {
        ErrorCode innerErrorCode =
            CredentialPojoUtils.isWeIdAuthenticationValid(weIdAuthentication);
        if (innerErrorCode != ErrorCode.SUCCESS) {
            return new ResponseData<>(null, innerErrorCode);
        }

        CreateCredentialPojoArgs args = new CreateCredentialPojoArgs();
        args.setClaim(authInfo);
        args.setWeIdAuthentication(weIdAuthentication);
        args.setId(UUID.randomUUID().toString());
        args.setContext(CredentialUtils.getDefaultCredentialContext());
        args.setCptId(CredentialConstant.AUTHORIZATION_CPT);
        String privateKey = weIdAuthentication.getWeIdPrivateKey().getPrivateKey();
        ECKeyPair keyPair = ECKeyPair.create(new BigInteger(privateKey));
        String keyWeId = WeIdUtils
            .convertAddressToWeId(new Address(Keys.getAddress(keyPair)).toString());
        args.setIssuer(keyWeId);
        args.setIssuanceDate(DateUtils.getNoMillisecondTimeStamp());
        args.setExpirationDate(args.getIssuanceDate() + authInfo.getDuration());
        ResponseData<CredentialPojo> resp = this.createCredential(args); // 生成 授权 Credential, DataAuthToken
        innerErrorCode = verifyAuthClaim(resp.getResult());
        if (innerErrorCode != ErrorCode.SUCCESS) {
            return new ResponseData<>(null, innerErrorCode);
        }
        return resp;
    }

}
