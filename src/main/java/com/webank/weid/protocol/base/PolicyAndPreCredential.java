/*
 *       Copyright© (2019) WeBank Co., Ltd.
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

import lombok.Getter;
import lombok.Setter;

import com.webank.weid.protocol.inf.JsonSerializer;

/**
 *
 * todo 策略和未完整的Credential
 *
 * policy and pre-credential.
 *
 * @author tonychen 2019年12月3日
 */
@Getter
@Setter
public class PolicyAndPreCredential implements JsonSerializer {

    /**
     * serial Version UID.
     */
    private static final long serialVersionUID = -5224072665022845706L;

    /**
     * policy and challenge.
     */
    // 策略或挑战
    private PolicyAndChallenge policyAndChallenge;

    /**
     * credential based on CPT 110.
     */
    // 基于 CPT 110 的 Credential
    private CredentialPojo preCredential;

    /**
     * extra data.
     */
    // 拓展信息
    private Map<String, String> extra;
}
