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

package com.webank.weid.protocol.base;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import lombok.Data;

/**
 * The base data structure to handle Credential EvidenceInfo info.
 *
 * @author chaoxinhu 2019.1
 */
@Data
public class EvidenceInfo {

    /**
     * 当前 Evidence 对应的 Credential 的全量Hash
     * Required: full Credential hash.
     */
    private String credentialHash;

    /**
     * 对 Evidence Hash 的签名信息
     * todo 可以知道 Evidence 中存储的 signature 可以使多个 ...
     * Required: sign info mapping (key: signer WeID, value: evidenceSignInfo).
     */
    private Map<String, EvidenceSignInfo> signInfo = new HashMap<>();

    /**
     * 获取所有的 签名人
     * Get all signers info.
     *
     * @return signers list
     */
    public List<String> getSigners() {
        List<String> signers = new ArrayList<>();
        for (Map.Entry<String, EvidenceSignInfo> entry : signInfo.entrySet()) {
            signers.add(entry.getKey());
        }
        return signers;
    }

    /**
     *
     * 获取所有的 签名信息
     * Get all signatures info.
     *
     * @return signatures list
     */
    public List<String> getSignatures() {
        List<String> signatures = new ArrayList<>();
        for (Map.Entry<String, EvidenceSignInfo> entry : signInfo.entrySet()) {
            signatures.add(entry.getValue().getSignature());
        }
        return signatures;
    }
}
