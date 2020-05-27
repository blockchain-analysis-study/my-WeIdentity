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

import lombok.Getter;
import lombok.Setter;

import com.webank.weid.protocol.inf.JsonSerializer;

/**
 * todo 策略或挑战 实体
 * Created by Junqi Zhang on 2019/4/10.
 */
@Setter
@Getter
public class PolicyAndChallenge implements JsonSerializer {

    /**
     * the serialVersionUID.
     */
    private static final long serialVersionUID = -7730049255207201464L;

    // PresentationPolicyE，是Presentation的“政策”。
    // 一般来说，我们在一项具体业务的时候，可能会让用户提交多个类型的凭证Credential，
    // 比如公司入职，可能会让你提交身份证凭证、学历证凭证、学位证凭证、offer letter凭证。
    // 具体提交什么样的凭证（cptId），每个凭证的关键属性项需要那些，就需要在policy里面提前定义好。
    private PresentationPolicyE presentationPolicyE;


    // Challenge，简单的来说，是用来在机构间使用AMOP通信的时候，通信的双方需要进行authentication (认证方式)。
    // 这里需要用到Challenge（密码学中的挑战一个概念）
    private Challenge challenge;
}

