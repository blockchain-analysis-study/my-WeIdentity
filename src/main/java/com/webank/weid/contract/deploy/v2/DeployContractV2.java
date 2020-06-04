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

package com.webank.weid.contract.deploy.v2;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;

import org.apache.commons.lang3.StringUtils;
import org.fisco.bcos.web3j.abi.datatypes.Address;
import org.fisco.bcos.web3j.crypto.Credentials;
import org.fisco.bcos.web3j.crypto.gm.GenCredential;
import org.fisco.bcos.web3j.protocol.Web3j;
import org.fisco.bcos.web3j.protocol.core.methods.response.TransactionReceipt;
import org.fisco.bcos.web3j.tx.gas.StaticGasProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.webank.weid.constant.WeIdConstant;
import com.webank.weid.contract.deploy.AddressProcess;
import com.webank.weid.contract.v2.AuthorityIssuerController;
import com.webank.weid.contract.v2.AuthorityIssuerData;
import com.webank.weid.contract.v2.CommitteeMemberController;
import com.webank.weid.contract.v2.CommitteeMemberData;
import com.webank.weid.contract.v2.CptController;
import com.webank.weid.contract.v2.CptData;
import com.webank.weid.contract.v2.EvidenceContract;
import com.webank.weid.contract.v2.EvidenceFactory;
import com.webank.weid.contract.v2.RoleController;
import com.webank.weid.contract.v2.SpecificIssuerController;
import com.webank.weid.contract.v2.SpecificIssuerData;
import com.webank.weid.contract.v2.WeIdContract;
import com.webank.weid.protocol.base.WeIdPrivateKey;
import com.webank.weid.service.BaseService;
import com.webank.weid.util.WeIdUtils;

/**
 * The Class DeployContract.
 *
 * @author tonychen
 */
public class DeployContractV2 extends AddressProcess {

    /**
     * log4j.
     */
    private static final Logger logger = LoggerFactory.getLogger(DeployContractV2.class);

    /**
     * The credentials.
     */
    private static Credentials credentials;

    /**
     * web3j object.
     */
    private static Web3j web3j;

    /**
     * 根据 输入的私钥, 生成公私钥对 ??
     *
     * Inits the credentials.
     *
     * @return true, if successful
     */
    private static boolean initCredentials(String inputPrivateKey) {
        if (StringUtils.isNotBlank(inputPrivateKey)) {
            logger.info("[DeployContractV2] begin to init credentials by privateKey..");
            credentials = GenCredential.create(new BigInteger(inputPrivateKey).toString(16));
        } else {
            logger.info("[DeployContractV2] begin to init credentials..");
            credentials = GenCredential.create();
        }

        if (credentials == null) {
            logger.error("[DeployContractV2] credentials init failed. ");
            return false;
        }

        // 关于 Credential 的公私钥对 ?? todo 干嘛的?
        String privateKey = credentials.getEcKeyPair().getPrivateKey().toString();
        String publicKey = credentials.getEcKeyPair().getPublicKey().toString();

        // 公私钥对 刷入本地文件
        writeAddressToFile(publicKey, "ecdsa_key.pub");
        writeAddressToFile(privateKey, "ecdsa_key");
        return true;
    }

    /**
     * Inits the web3j.
     */
    protected static void initWeb3j() {
        if (web3j == null) {
            web3j = (Web3j) BaseService.getWeb3j();
        }
    }

    /**
     *
     * todo 往 FISCO BCOS 2.0 部署合约
     * depoly contract on FISCO BCOS 2.0.
     * @param privateKey the private key
     */
    public static void deployContract(String privateKey) {
        // 初始化 Web3J
        initWeb3j();

        // todo 初始化 Credential 需要的 公私钥对??
        initCredentials(privateKey);

        // 部署 WeId 合约
        String weIdContractAddress = deployWeIdContract();

        // 部署 角色控制 合约
        String roleControllerAddress = deployRoleControllerContracts();

        // 部署 发行人 相关合约
        Map<String, String> addrList = deployIssuerContracts(roleControllerAddress);
        if (addrList.containsKey("AuthorityIssuerData")) {
            String authorityIssuerDataAddress = addrList.get("AuthorityIssuerData");

            // 根据 权威发行人 数据合约地址, 部署CPT 相关合约
            deployCptContracts(
                authorityIssuerDataAddress,
                weIdContractAddress,
                roleControllerAddress
            );
        }

        // 部署 Evidence 合约
        deployEvidenceContractsNew();

        // todo 根据私钥将合约地址注册到cns中
        registerToCns();
    }

    // 根据私钥将合约地址注册到cns中
    private static void registerToCns() {
        String privateKey = AddressProcess.getAddressFromFile("ecdsa_key");
        WeIdPrivateKey weIdPrivate = new WeIdPrivateKey();
        weIdPrivate.setPrivateKey(privateKey);
        // Do it ...
        RegisterAddressV2.registerAddress(weIdPrivate);
    }
    

    private static String deployRoleControllerContracts() {
        if (web3j == null) {
            initWeb3j();
        }
        RoleController roleController = null;
        try {
            roleController =
                RoleController.deploy(
                    web3j,
                    credentials,
                    new StaticGasProvider(WeIdConstant.GAS_PRICE, WeIdConstant.GAS_LIMIT)
                ).send();
            return roleController.getContractAddress();
        } catch (Exception e) {
            logger.error("RoleController deploy exception", e);
            return StringUtils.EMPTY;
        }
    }

    /**
     * TODO 部署 WeId 合约
     * @return
     */
    private static String deployWeIdContract() {
        if (web3j == null) {
            initWeb3j();
        }

        WeIdContract weIdContract = null;
        try {
            weIdContract = WeIdContract.deploy(
                web3j,
                credentials,
                new StaticGasProvider(WeIdConstant.GAS_PRICE, WeIdConstant.GAS_LIMIT))
                .send();
        } catch (Exception e) {
            logger.error("WeIdContract deploy error.", e);
            return StringUtils.EMPTY;
        }

        String contractAddress = weIdContract.getContractAddress();
        writeAddressToFile(contractAddress, "weIdContract.address");
        return contractAddress;

    }

    private static String deployCptContracts(
        String authorityIssuerDataAddress,
        String weIdContractAddress,
        String roleControllerAddress) {
        if (web3j == null) {
            initWeb3j();
        }

        try {
            // 部署 CPT 数据合约
            CptData cptData =
                CptData.deploy(
                    web3j,
                    credentials,
                    new StaticGasProvider(WeIdConstant.GAS_PRICE, WeIdConstant.GAS_LIMIT),
                    authorityIssuerDataAddress).send();
            String cptDataAddress = cptData.getContractAddress();

            // 部署 CPT控制合约
            CptController cptController =
                CptController.deploy(
                    web3j,
                    credentials,
                    new StaticGasProvider(WeIdConstant.GAS_PRICE, WeIdConstant.GAS_LIMIT),
                    cptDataAddress,
                    weIdContractAddress
                ).send();
            String cptControllerAddress = cptController.getContractAddress();
            writeAddressToFile(cptControllerAddress, "cptController.address");

            TransactionReceipt receipt =
                cptController.setRoleController(roleControllerAddress).send();
            if (receipt == null) {
                logger.error("CptController deploy exception");
            }
        } catch (Exception e) {
            logger.error("CptController deploy exception", e);
        }

        return StringUtils.EMPTY;
    }

    // 部署 发行人相关合约
    private static Map<String, String> deployIssuerContracts(String roleControllerAddress) {
        if (web3j == null) {
            initWeb3j();
        }
        Map<String, String> issuerAddressList = new HashMap<>();

        String committeeMemberDataAddress;
        try {
            // 部署 委员会数据 合约
            CommitteeMemberData committeeMemberData = CommitteeMemberData.deploy(
                web3j,
                credentials,
                new StaticGasProvider(WeIdConstant.GAS_PRICE, WeIdConstant.GAS_LIMIT),
                roleControllerAddress).send();
            committeeMemberDataAddress = committeeMemberData.getContractAddress();
            if (!WeIdUtils.isEmptyAddress(new Address(committeeMemberDataAddress))) {
                issuerAddressList.put("CommitteeMemberData", committeeMemberDataAddress);
            }
        } catch (Exception e) {
            logger.error("CommitteeMemberData deployment error:", e);
            return issuerAddressList;
        }

        String committeeMemberControllerAddress;
        try {

            // 部署 委员会控制 合约
            CommitteeMemberController committeeMemberController = CommitteeMemberController.deploy(
                web3j,
                credentials,
                new StaticGasProvider(WeIdConstant.GAS_PRICE, WeIdConstant.GAS_LIMIT),
                committeeMemberDataAddress,
                roleControllerAddress
            ).send();
            committeeMemberControllerAddress = committeeMemberController.getContractAddress();
            if (!WeIdUtils.isEmptyAddress(new Address(committeeMemberControllerAddress))) {
                issuerAddressList
                    .put("CommitteeMemberController", committeeMemberControllerAddress);
            }
        } catch (Exception e) {
            logger.error("CommitteeMemberController deployment error:", e);
            return issuerAddressList;
        }

        String authorityIssuerDataAddress;
        try {

            // 部署 权威发行人数据 合约
            AuthorityIssuerData authorityIssuerData = AuthorityIssuerData.deploy(
                web3j,
                credentials,
                new StaticGasProvider(WeIdConstant.GAS_PRICE, WeIdConstant.GAS_LIMIT),
                roleControllerAddress
            ).send();
            authorityIssuerDataAddress = authorityIssuerData.getContractAddress();
            if (!WeIdUtils.isEmptyAddress(new Address(authorityIssuerDataAddress))) {
                issuerAddressList.put("AuthorityIssuerData", authorityIssuerDataAddress);
            }
        } catch (Exception e) {
            logger.error("AuthorityIssuerData deployment error:", e);
            return issuerAddressList;
        }

        String authorityIssuerControllerAddress;
        try {

            // 部署 权威发行人控制 合约
            AuthorityIssuerController authorityIssuerController = AuthorityIssuerController.deploy(
                web3j,
                credentials,
                new StaticGasProvider(WeIdConstant.GAS_PRICE, WeIdConstant.GAS_LIMIT),
                authorityIssuerDataAddress,
                roleControllerAddress).send();
            authorityIssuerControllerAddress = authorityIssuerController.getContractAddress();
            if (!WeIdUtils.isEmptyAddress(new Address(authorityIssuerControllerAddress))) {
                issuerAddressList
                    .put("AuthorityIssuerController", authorityIssuerControllerAddress);
            }
        } catch (Exception e) {
            logger.error("AuthorityIssuerController deployment error:", e);
            return issuerAddressList;
        }

        try {
            // 将当前 权威发行人控制合约 地址刷入本地文件
            writeAddressToFile(authorityIssuerControllerAddress, "authorityIssuer.address");
        } catch (Exception e) {
            logger.error("Write error:", e);
        }

        String specificIssuerDataAddress = StringUtils.EMPTY;
        try {

            // 部署 发行人描述信息数据 合约
            SpecificIssuerData specificIssuerData = SpecificIssuerData.deploy(
                web3j,
                credentials,
                new StaticGasProvider(WeIdConstant.GAS_PRICE, WeIdConstant.GAS_LIMIT)
            ).send();
            specificIssuerDataAddress = specificIssuerData.getContractAddress();
            if (!WeIdUtils.isEmptyAddress(new Address(specificIssuerDataAddress))) {
                issuerAddressList.put("SpecificIssuerData", specificIssuerDataAddress);
            }
        } catch (Exception e) {
            logger.error("SpecificIssuerData deployment error:", e);
        }

        try {
            // 部署 发行人描述信息控制 合约
            SpecificIssuerController specificIssuerController = SpecificIssuerController.deploy(
                web3j,
                credentials,
                new StaticGasProvider(WeIdConstant.GAS_PRICE, WeIdConstant.GAS_LIMIT),
                specificIssuerDataAddress,
                roleControllerAddress
            ).send();
            String specificIssuerControllerAddress = specificIssuerController.getContractAddress();
            if (!WeIdUtils.isEmptyAddress(new Address(specificIssuerControllerAddress))) {
                issuerAddressList.put("SpecificIssuerController", specificIssuerControllerAddress);
            }
            try {
                writeAddressToFile(specificIssuerControllerAddress, "specificIssuer.address");
            } catch (Exception e) {
                logger.error("Write error:", e);
            }
        } catch (Exception e) {
            logger.error("SpecificIssuerController deployment error:", e);
        }
        return issuerAddressList;
    }

    @Deprecated
    private static String deployEvidenceContracts() {
        if (web3j == null) {
            initWeb3j();
        }
        try {
            EvidenceFactory evidenceFactory =
                EvidenceFactory.deploy(
                    web3j,
                    credentials,
                    new StaticGasProvider(WeIdConstant.GAS_PRICE, WeIdConstant.GAS_LIMIT)
                ).send();
            String evidenceFactoryAddress = evidenceFactory.getContractAddress();
            writeAddressToFile(evidenceFactoryAddress, "evidenceController.address");
            return evidenceFactoryAddress;
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            logger.error("EvidenceFactory deploy exception", e);
        } catch (Exception e) {
            logger.error("EvidenceFactory deploy exception", e);
        }
        return StringUtils.EMPTY;
    }

    private static String deployEvidenceContractsNew() {
        if (web3j == null) {
            initWeb3j();
        }
        try {
            // 部署 Evidence 合约
            EvidenceContract evidenceContract =
                EvidenceContract.deploy(
                    web3j,
                    credentials,
                    new StaticGasProvider(WeIdConstant.GAS_PRICE, WeIdConstant.GAS_LIMIT)
                ).send();
            String evidenceContractAddress = evidenceContract.getContractAddress();
            writeAddressToFile(evidenceContractAddress, "evidenceController.address");
            return evidenceContractAddress;
        } catch (Exception e) {
            logger.error("EvidenceFactory deploy exception", e);
        }
        return StringUtils.EMPTY;
    }
}