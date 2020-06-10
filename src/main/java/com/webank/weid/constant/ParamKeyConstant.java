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

package com.webank.weid.constant;

/**
 * Define param key names to be allowed to enable calls to Java SDK.
 *
 * @author chaoxinhu
 */
public final class ParamKeyConstant {

    /**
     * Universal param key names.
     */
    public static final String WEID = "weId";

    /**
     * WeIdService related param names.
     */
    public static final String PUBLIC_KEY = "publicKey";

    /**
     * AuthorityIssuer related param names.
     */
    public static final String AUTHORITY_ISSUER_NAME = "name";

    /**
     * UTF-8.
     */
    public static final String UTF_8 = "UTF-8";

    /**
     * CptService related param names.
     */
    public static final String CPT_JSON_SCHEMA = "cptJsonSchema";
    public static final String CPT_SIGNATURE = "cptSignature";
    public static final String CPT = "Cpt";

    /**
     * CredentialService related param names.
     */
    public static final String CPT_ID = "cptId";
    public static final String ISSUER = "issuer";
    public static final String CLAIM = "claim";
    public static final String EXPIRATION_DATE = "expirationDate";
    public static final String CREDENTIAL_SIGNATURE = "signature";
    public static final String CONTEXT = "context";
    public static final String CREDENTIAL_ID = "id";
    public static final String ISSUANCE_DATE = "issuanceDate";
    public static final String POLICY = "Policy";
    public static final String POLICY_PACKAGE = "com.webank.weid.cpt.policy.";

    /**
     * todo  Credential 和 Presentation 中的 proof 的字段 (VC 和 VP 两者的 Proof 字段基本上一样)
     * proof key.
     */
    public static final String PROOF = "proof";                                             // W3C 标准字段, proof  (presentation 和 credential 都有)
    public static final String PROOF_SIGNATURE = "signatureValue";                          // 微众自定义, (对应W3C的 jws ?), proof中存放的 sign值 (presentation 和 credential 都有)
    public static final String PROOF_TYPE = "type";                                         // W3C 标准字段, proof中存放 sign生成的算法方式 (presentation 和 credential 都有)
    public static final String PROOF_CREATED = "created";                                   // W3C 标准字段, proof中存放的 (presentation 和 credential 都有)
    public static final String PROOF_CREATOR = "creator";                                   // 微众自定义, credential.Proof 独有
    public static final String PROOF_SALT = "salt";                                         // 微众自定义, 只有 CredentialPojo 要
    public static final String PROOF_VERIFICATION_METHOD = "verificationMethod";            // W3C标准, proof中存放  `did:example:ebfeb1f712ebc6f1c276e12ec21#keys-1` 形式
    public static final String PROOF_NONCE = "nonce";                                       // 微众自定义, 对应 W3C 中的 challenge字段, 只有 Presentation 使用
    public static final String PROOF_VERIFICATIONREQUEST = "verificationRequest";           // 微众自定义, 微众的 零知识证明 Credential 的字段, 和 `encodedVerificationRule` 配套
    public static final String PROOF_ENCODEDVERIFICATIONRULE = "encodedVerificationRule";   // 微众自定义, 微众的 零知识证明 Credential 的字段, 和 `verificationRequest` 配套


    /**
     * 秘钥存储KEY.
     */
    public static final String KEY_DATA = "keyData";
    public static final String KEY_VERIFIERS = "verifiers";
    public static final String KEY_EXPIRE = "expirationDate";
    public static final String MASTER_SECRET = "masterSecret";
    public static final String BLINDING_FACTORS = "credentialSecretsBlindingFactors";

    public static final String WEID_AUTH_OBJ = "weIdAuthObj";
    public static final String WEID_AUTH_SIGN_DATA = "signData";
    public static final String WEID_AUTH_CHALLENGE = "challenge";

    public static final String TRNSACTION_RECEIPT_STATUS_SUCCESS = "0x0";
    
    /**
     * 内置配置Key.
     */
    public static final String RSYNC_IP = "rsyncIp";
    public static final String RSYNC_PORT = "rsyncPort";
    public static final String RSYNC_USER = "rsyncUser";
    public static final String RSYNC_PWD_NAME = "rsyncPwdName";
    public static final String RSYNC_BIN_LOG_MODULE = "binLog";
    public static final String BIN_LOG_PATH = "binLogPath";
    public static final String ENABLE_OFFLINE = "enableOffLine";
    public static final String INTEVAL_PERIOD = "inteval_period";
    
}
