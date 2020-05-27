/*
 *       Copyright© (2018) WeBank Co., Ltd.
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

import lombok.Data;

/**
 *
 * todo 处理WeIdentity DID授权信息的基本数据结构。
 * The base data structure to handle WeIdentity DID authority info.
 *
 * todo WeIdentity 体系的 WeId认证方式实体
 *
 * @author darwindu
 */
@Data
public class WeIdAuthentication {

    /**
     * 认证方式
     * Required: The weIdentity DID.
     */
    private String weId;
    
    /**
     *
     * 和该 WeId 绑定的 公钥
     * the public key Id.
     */
    private String weIdPublicKeyId;

    /**
     *
     * 和公钥配套的 私钥
     * Required: The private key or The weIdentity DID.
     */
    private WeIdPrivateKey weIdPrivateKey;
    
    public WeIdAuthentication() {
        super();
    }
    
    /**
     * Constructor with weId and privateKey. 
     * @param weId the weId
     * @param privateKey the privateKey
     */
    public WeIdAuthentication(String weId, String privateKey) {
        this.weId = weId;
        this.weIdPrivateKey = new WeIdPrivateKey();
        this.weIdPrivateKey.setPrivateKey(privateKey);
    }
    
    /**
     * Constructor with weId, privateKey and weIdPublicKeyId. 
     * @param weId the weId
     * @param privateKey the privateKey
     * @param weIdPublicKeyId the weIdPublicKeyId
     */
    public WeIdAuthentication(String weId, String privateKey, String weIdPublicKeyId) {
        this(weId, privateKey);
        this.weIdPublicKeyId = weIdPublicKeyId;
    }
}
