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

import java.util.Map;

import lombok.Data;
import org.apache.commons.lang3.StringUtils;

import com.webank.weid.constant.ErrorCode;
import com.webank.weid.protocol.inf.Hashable;
import com.webank.weid.util.CredentialUtils;

/**
 * Credential response.
 *
 * todo 对Credential的封装类, 包含了 Credential类 和 披露信息
 *
 * @author tonychen 2019年1月24日
 */
@Data
public class CredentialWrapper implements Hashable {

    /**
     *
     * TODO 基本的 Credential类, 注意: 不是对外的 CredentialPojo 哦
     *
     * todo 其中的 Claim 字段上的 值, 可以是 全披露的/ 也可以是 选择性披露的
     * Required: The Credential.
     */
    private Credential credential;

    /**
     *
     * todo 选择披露字段
     * Required: key is the credential field, and value "1" for disclosure to the third party, "0"
     * for no disclosure.
     *
     * todo 必填：键是凭据字段，值“ 1”用于向第三方公开，“ 0”用于不公开
     */
    private Map<String, Object> disclosure;

    /**
     * Generate the unique hash of this CredentialWrapper.
     *
     * @return hash value
     */
    public String getHash() {
        if (this == null) {
            return StringUtils.EMPTY;
        }
        if (this.getDisclosure() == null || this.getDisclosure().size() == 0) {
            return this.getCredential().getHash();
        }
        Credential credential = this.getCredential();
        if (CredentialUtils.isCredentialValid(credential) != ErrorCode.SUCCESS) {
            return StringUtils.EMPTY;
        }
        return CredentialUtils.getCredentialWrapperHash(this);
    }

    /**
     * Directly extract the signature value from credential.
     *
     * @return signature value
     */
    public String getSignature() {
        return credential.getSignature();
    }

    /**
     * Get the signature thumbprint for re-signing.
     *
     * @return thumbprint
     */
    public String getSignatureThumbprint() {
        return CredentialUtils.getCredentialThumbprint(this.getCredential(), this.getDisclosure());
    }
}
