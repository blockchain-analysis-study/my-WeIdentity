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

package com.webank.weid.protocol.base;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.fge.jackson.JsonLoader;
import lombok.Data;
import lombok.EqualsAndHashCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.webank.weid.constant.CredentialConstant;
import com.webank.weid.protocol.inf.JsonSerializer;
import com.webank.weid.util.DataToolUtils;

/**
 *
 * todo 策略表现形式
 *
 * PresentationPolicyE，是Presentation的“政策”。一般来说，
 * 我们在一项具体业务的时候，可能会让用户提交多个类型的凭证Credential，
 * 比如公司入职，可能会让你提交身份证凭证、学历证凭证、学位证凭证、offer letter凭证。
 * 具体提交什么样的凭证（cptId），每个凭证的关键属性项需要那些，就需要在policy里面提前定义好。
 *
 * The base data structure to handle Credential info.
 *
 * @author junqizhang 2019.04
 */
@Data
@EqualsAndHashCode(callSuper = true)
public class PresentationPolicyE extends Version implements JsonSerializer {
    
    /**
     * the serialVersionUID.
     */
    private static final long serialVersionUID = 3607089314849566766L;

    private static final Logger logger = LoggerFactory.getLogger(PresentationPolicyE.class);

    /**
     * Policy ID.
     */
    private Integer id;

    /**
     * todo 代表谁发布此 表现形式政策
     * represent who publish this presentation policy.
     */
    private String orgId;

    /**
     *
     * todo 代表谁(WeId)发布此 表现形式政策
     * represent who publish this presentation policy.
     */
    private String policyPublisherWeId;

    /**
     *
     * todo 指定需要哪些属性的credential
     *  (cptId => ClaimPolicy <这是一个 jsonStr>) 定义了 选择性披露的 policy
     * specify which properties in which credential are needed.
     */
    private Map<Integer, ClaimPolicy> policy;

    /**
     *
     * todo 策略演示者可以使用的其他数据存储一些特定的业务数据。
     * extra data which policy presenter can use it store some specific business data.
     */
    private Map<String, String> extra;

    /**
     * todo 新增字段，标识是支持 `零知识证明的policy` 还是 `原来的`.
     */
    private String policyType = "original";

    /**
     * close the constructor.
     */
    private PresentationPolicyE() {
    }

    /**
     *
     * todo 使用policyFileName创建 PresentationPolicyE，请确保您的classPath中有JSON文件。
     *
     * create the PresentationPolicyE with policyFileName, 
     * please make sure the JSON file in your classPath.
     * 
     * @param policyFileName the policyFileName
     * @return the PresentationPolicyE
     */
    public static PresentationPolicyE create(String policyFileName) {
        PresentationPolicyE policy = null;
        try {
            JsonNode jsonNode = null;
            //获取policyJson文件 转换成JsonNode
            File file = new File(policyFileName);
            if (file.exists()) {
                jsonNode = JsonLoader.fromFile(file);
            } else {
                jsonNode = JsonLoader.fromResource("/" + policyFileName);
            }
           
            if (jsonNode == null) {
                logger.error("can not find the {} file in your classpath.", policyFileName);
                return policy;
            }
            policy = fromJson(jsonNode.toString());
        } catch (IOException e) {
            logger.error("create PresentationPolicyE has error, please check the log.", e);
        }
        return policy;
    }
    
    /**
     *
     * TODO 根据 JSON String 创建  表现形式策略
     *
     * create the PresentationPolicyE with JSON String.
     * 
     * @param json the JSON String
     * @return the PresentationPolicyE
     */
    public static PresentationPolicyE fromJson(String json) {
        PresentationPolicyE policy = null;
        try {
            //将Json转换成Map
            HashMap<String, Object> policyMap = 
                DataToolUtils.deserialize(json, HashMap.class);
            //获取policyJson中的policy 转换成Map
            //
            // 提取 当前 policy 中指定的 cpt 集
            HashMap<Integer, Object> claimMap = 
                (HashMap<Integer, Object>)policyMap.get(CredentialConstant.CLAIM_POLICY_FIELD);
            //遍历claimMap
            Iterator<Integer> it = claimMap.keySet().iterator();
            while (it.hasNext()) {
                //得到每一个claim
                HashMap<String, Object> claim = (HashMap<String, Object>)claimMap.get(it.next());
                //得到fieldsToBeDisclosed转换成Map
                //
                // 提取每个 claim中的 披露字段
                HashMap<String, Object> disclosedMap = 
                    (HashMap<String, Object>)claim.get(
                        CredentialConstant.CLAIM_POLICY_DISCLOSED_FIELD
                    );

                //覆盖原来的fieldsToBeDisclosed为字符串
                claim.put(
                    CredentialConstant.CLAIM_POLICY_DISCLOSED_FIELD,
                    DataToolUtils.serialize(disclosedMap)
                );
            }
            //重新序列化为policyJson
            String value = DataToolUtils.serialize(policyMap);
            //反序列化policyJson为PresentationPolicyE
            return DataToolUtils.deserialize(value, PresentationPolicyE.class);
        } catch (Exception e) {
            logger.error("create PresentationPolicyE has error, please check the log.", e);
        }
        return policy;
    }
    
    @Override
    public String toJson() {
        String jsonString = DataToolUtils.serialize(this);
        HashMap<String, Object> policyEMap = DataToolUtils.deserialize(jsonString, HashMap.class);
        Map<String, Object> policy1 = 
            (HashMap<String, Object>)policyEMap.get(CredentialConstant.CLAIM_POLICY_FIELD);
        for (Map.Entry<String, Object> entry : policy1.entrySet()) {
            HashMap<String, Object> claimPolicyMap = (HashMap<String, Object>)entry.getValue();
            HashMap<String, Object> disclosureMap = 
                DataToolUtils.deserialize(
                    (String)claimPolicyMap.get(CredentialConstant.CLAIM_POLICY_DISCLOSED_FIELD),
                    HashMap.class
                );
            claimPolicyMap.put(CredentialConstant.CLAIM_POLICY_DISCLOSED_FIELD, disclosureMap);
        }
        return DataToolUtils.serialize(policyEMap);
    }
}
