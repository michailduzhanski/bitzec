// Bismilah


// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#include "key_io.h"
#include "main.h"
#include "crypto/equihash.h"

#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

#include "chainparamsseeds.h"

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, const uint256& nNonce, const std::vector<unsigned char>& nSolution, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    // To create a genesis block for a new chain which is Overwintered:
    //   txNew.nVersion = OVERWINTER_TX_VERSION
    //   txNew.fOverwintered = true
    //   txNew.nVersionGroupId = OVERWINTER_VERSION_GROUP_ID
    //   txNew.nExpiryHeight = <default value>
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 520617983 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nSolution = nSolution;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(txNew);
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = genesis.BuildMerkleTree();
    return genesis;
}


 /* Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database (and is in any case of zero value).
 */

 /**
 *
 *  >>> 'Arnak' (b'the binary digit zero knowledge electronic currency')
 *
 * CBlock(hash=00040fe8, ver=4, hashPrevBlock=00000000000000, hashMerkleRoot=c4eaa5, nTime=1573320600, nBits=1f07ffff, nNonce=4695, vtx=1)
 *   CTransaction(hash=c4eaa5, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff071f0104455a6361736830623963346565663862376363343137656535303031653335303039383462366665613335363833613763616331343161303433633432303634383335643334)
 *     CTxOut(nValue=0.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: c4eaa5
 */

static CBlock CreateGenesisBlock(uint32_t nTime, const uint256& nNonce, const std::vector<unsigned char>& nSolution, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp ="Arnak12ec09992caa4e9654162692c5ca2ddeb385a462974fdc660df08e23ae870d4c" ;
    const CScript genesisOutputScript = CScript() << ParseHex("045d5f19f31313a629158bb6dbcde0fee7e01b0f027711353b5d8ad4edeed2c2817ba5b20991a4a6acb8aa65d6de47c1dfce98b8ebd7993fc4f3c2b61cd40074c2") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nSolution, nBits, nVersion, genesisReward);
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

const arith_uint256 maxUint = UintToArith256(uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        strCurrencyUnits = "ARK"; // the binary digit zero knowledge electronic currency
        bip44CoinType = 133; // As registered in https://github.com/satoshilabs/slips/blob/master/slip-0044.md
        consensus.fCoinbaseMustBeProtected = true;
        consensus.nSubsidySlowStartInterval = 7;
        consensus.nSubsidyHalvingInterval = 1000000;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 4000;
        const size_t N = 200, K = 9;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        consensus.nEquihashN = N;
        consensus.nEquihashK = K;
        consensus.powLimit = uint256S("0007ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowAveragingWindow = 17;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 32; // 32% adjustment down
        consensus.nPowMaxAdjustUp = 16; // 16% adjustment up
        consensus.nPowTargetSpacing = 1 * 60;
        consensus.nPowAllowMinDifficultyBlocksAfterHeight = boost::none;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nActivationHeight =
            Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nProtocolVersion = 175001;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nActivationHeight = 3;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nProtocolVersion = 175001;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight = 5;
	consensus.vUpgrades[Consensus::UPGRADE_BLOSSOM].nProtocolVersion = 170002;
            consensus.vUpgrades[Consensus::UPGRADE_BLOSSOM].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
  // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        /**
         * The message start string should be awesome! Bⓩ❤
         */
        pchMessageStart[0] = 0x21;
        pchMessageStart[1] = 0xe7;
        pchMessageStart[2] = 0x27;
        pchMessageStart[3] = 0x61;
        vAlertPubKey = ParseHex("04dca46fa5ca4600ab464f748967f34ee5134f477169d9818467f7abd79cb824ad3d51672c366864ae397b2d01819715c21ad2313cc095928658b5bf5ea1c545eb");
        nDefaultPort = 15203;
        nPruneAfterHeight = 100000;

        genesis = CreateGenesisBlock(
            1573320600,
            uint256S("0x0000000000000000000000000000000000000000000000000000000000000364"),
            ParseHex("0065f767a58b8ce5475662c9f8e438a6b2871909031b6e66b2b9bcbaadf918622b02c58c84f88f0cbe720af5653e765e9ac599a3257bd2b4d8bab4801824612a9c5e68ec0ba7d2683073a502eba6262f8ed8650f088f65ac19d537af47d860fe38b2432a7c715bbcd51f830d8d8e980633aa1f221d24929468d280691b19132a03f1fad629d374fb62afb91d953e355fd2d588447dde5e05a3c12b997066026ce5da7da07aad873600a768c26a1ed871901c080616c40d2395697e9f983dee7ae1951e3325de5aa7bde379f8be6d911b965e2b09eec4ca8b6847b88aa60ddfdd9a5f73429ef7943ca07c9c71b0fc97d27c553379540611cdaa8ed9740cf8571b040bda2dbcf7c1c912a586a197758ccbd32252becc10eb2bddaf1bf3e7403785114afad81678241caf6a3fa27bb1a3b93309d7d56e455e0dfe49d32797e5b67b16fb32cbbff30d644562115679bb98f2029881ff064f10acd03d3284b0adbc7a9724bb9cb90521c075bf151289779bf36565489b66d8da9e77220744a6fa8d880f7e5466c1a0031ab0464eaa9aebf00e3b9cea64dfc82d2b4226027bb2ae566ebad498af050f67d915c84aff2bb2d714cc393bcb04ffff510b062431556599d5bb69a5b2df72f4842925197d132313d71adddffb1c19f89fa28d184b1799d8fb8fe6723b643de4fe91f816f1b0f4dc01e51ba9d07532b15d037164467cc84f2af991d3de8ee6b1296ad370050009786ee88c11d5e181e920da99671030aee9394029088a6ad5fb48b700b56871372622d100682863f64a37b75b457ca850f17a686805e8e9dbf2266afda7eb0a7686b755c3dc80c196d3d686d7ccbe00451e5b21491c95fd0b6abbd37438e63b30542e9ed0f4798b811d30c1c84a98f2df3799e89304f5f2b282f596df1d1d3f27f427a7bd0fcbc5293e9455064268385f237500a7196b3eac59b1dc63b42b20b6d4dd89b8b17ed11e005b60a64e054b2618d25796f763da8d199af799283c19af6c6bc241d046a2f549378c990fec54f1bb5ef88597245b1ea59fea98b59ce1b3daf369d802cb0c5ac7374f65307bb045b45af2c8f1415fc56f667e10aef7f5c1a2f9f9e7f704999d66ae1d4cabba45530d68a96b80e82fdfa43c820c4fc9c67d43cf5734ef328873775c909ce5874d56adb2bc61bb05185eef2509728d668bd33db55a3379cd6ee382a2bd1e7cd1811cca46051c5031d16c194206ba64b684e6e86f426e21f92d79fbed65a1eb93551cd0e662715d37959ef93420f7a17d135691e20db3a5ef4688072452fd79610fae9977df4596f704b9e2ffc35fc720f5150a33903faf164191f38abdaffe447234d95c3218fa7c90c31aee82b2f96243a336f64414d14f2c8b55e97b27ce1fafbb839ad769afffae5226ca4fb91785b97d95d901f8be3ed21567691e7094c3727bf4c55323ed86bb1eadcd5043c8a79bff91f2ba08e42d6ad4ea9da7df052e1fb1a9ca76c734ffc2f7ecc63edcdc98e916042a6551690d92c4f9aa93f5c3f14337f6c7d2fb197b1b224c6f9b086d0de92b643d8d518be9b84b7cbd6e203c15939f8ca769d247134b15419ef160d56e1e761cd755edd089b6dc779ae633ea711a9231e272727a3f041680bfaec7d1ce8335069079e516b1983c331a01fac6db8c59ea67e74f21cf164dcd0143c4f21dbc33ff927423246cf7481f9a8e22e93be2df7ada6a660ced37a0f5a90565adea227045dfeb6556f477c8181515d2933e1801bd3bdc11c3b8c337d5907255a3cb03feb8c13fe119d73a52b2298434e5c1ea3a3399db207c836554963dd97fb7a2f244709e323a57130f830536ca1c11cdf33f49cf81de231d5db2c89d7df36516744bec26e1d85367c068329bff73861d7b76980a"),
            0x1f07ffff, 4, 0);
        consensus.hashGenesisBlock = genesis.GetHash();
		printf("block.nTime = %u \n", genesis.nTime);
		printf("block.nNonce = %s \n", genesis.nNonce.ToString().c_str());
		printf("block.GetHash = %s\n", genesis.GetHash().ToString().c_str());
		printf("block.merkle = %s\n", genesis.hashMerkleRoot.ToString().c_str());
        assert(consensus.hashGenesisBlock == uint256S("0x0000bbe7305332fcdd04b1ad4df19d9800ceae21488a3958e0f39886e782a2ce"));
        assert(genesis.hashMerkleRoot == uint256S("0xe61b7d3ec8da5e04425f30cfd83e2524ad0b11d1d62bb9f0776b8372af4cc876"));

        vFixedSeeds.clear();
        vSeeds.clear();
        //vSeeds.push_back(CDNSSeedData("arnak.org", "seed.arnak.org")); //
        //vSeeds.push_back(CDNSSeedData("35.242.189.203", "35.242.189.203"));
        //vSeeds.push_back(CDNSSeedData("151.106.63.210", "151.106.63.210")); //seed node  equihub
        //vSeeds.push_back(CDNSSeedData("bzcseed.raptorpool.org", "bzcseed.raptorpool.org")); // seed node  raptorpool

        //vSeeds.push_back(CDNSSeedData("str4d.xyz", "dnsseed.str4d.xyz")); // @str4d
        //vSeeds.push_back(CDNSSeedData("znodes.org", "dnsseed.znodes.org")); // @bitcartel

        // guarantees the first 2 characters, when base58 encoded, are "t1"
        base58Prefixes[PUBKEY_ADDRESS]     = {0x1C,0xB8};
        // guarantees the first 2 characters, when base58 encoded, are "t3"
        base58Prefixes[SCRIPT_ADDRESS]     = {0x1C,0xBD};
        // the first character, when base58 encoded, is "5" or "K" or "L" (as in Bitcoin)
        base58Prefixes[SECRET_KEY]         = {0x80};
        // do not rely on these BIP32 prefixes; they are not specified and may change
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x04,0x88,0xB2,0x1E};
        base58Prefixes[EXT_SECRET_KEY]     = {0x04,0x88,0xAD,0xE4};
        // guarantees the first 2 characters, when base58 encoded, are "zc"
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {0x16,0x9A};
        // guarantees the first 4 characters, when base58 encoded, are "ZiVK"
        base58Prefixes[ZCVIEWING_KEY]      = {0xA8,0xAB,0xD3};
        // guarantees the first 2 characters, when base58 encoded, are "SK"
        base58Prefixes[ZCSPENDING_KEY]     = {0xAB,0x36};

        bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "zs";
        bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "zviews";
        bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "zivks";
        bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "secret-extended-key-main";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = false;

         checkpointData = (CCheckpointData) {
             boost::assign::map_list_of
             //(0, consensus.hashGenesisBlock)
             ( 0, consensus.hashGenesisBlock),
             genesis.nTime,
             0,
             0
        };

        // Hardcoded fallback value for the Sprout shielded value pool balance
        // for nodes that have not reindexed since the introduction of monitoring
        // in #2795.
        nSproutValuePoolCheckpointHeight = 520633;
        nSproutValuePoolCheckpointBalance = 22145062442933;
        fZIP209Enabled = true;
        hashSproutValuePoolCheckpointBlock = uint256S("0000000000c7b46b6bc04b4cbf87d8bb08722aebd51232619b214f7273f8460e");

        // Founders reward script expects a vector of 2-of-3 multisig addresses
        vFoundersRewardAddress = {
//            "t1fNjYzExUXxwZxB8uMGt8fRYzD1UG9PzrK", /* main-index: 0*/
 //           "t1b77XjiifeVX2NUD9s8SH7rAF2WsAYirws", /* main-index: 1*/
//            "t1N13KEG8izgYeW2J9mhLHLUrh5fYxPwguE", /* main-index: 2*/
//            "t1fNjYzExUXxwZxB8uMGt8fRYzD1UG9PzrK", /* main-index: 3*/
//            "t1b77XjiifeVX2NUD9s8SH7rAF2WsAYirws", /* main-index: 4*/
//            "t1N13KEG8izgYeW2J9mhLHLUrh5fYxPwguE", /* main-index: 5*/
//            "t1fNjYzExUXxwZxB8uMGt8fRYzD1UG9PzrK", /* main-index: 6*/
//            "t1b77XjiifeVX2NUD9s8SH7rAF2WsAYirws", /* main-index: 7*/
//            "t1N13KEG8izgYeW2J9mhLHLUrh5fYxPwguE", /* main-index: 8*/
//            "t1fNjYzExUXxwZxB8uMGt8fRYzD1UG9PzrK", /* main-index: 9*/
//            "t1b77XjiifeVX2NUD9s8SH7rAF2WsAYirws", /* main-index: 10*/
//            "t1N13KEG8izgYeW2J9mhLHLUrh5fYxPwguE", /* main-index: 11*/
//            "t1fNjYzExUXxwZxB8uMGt8fRYzD1UG9PzrK", /* main-index: 12*/
//            "t1b77XjiifeVX2NUD9s8SH7rAF2WsAYirws", /* main-index: 13*/
//            "t1N13KEG8izgYeW2J9mhLHLUrh5fYxPwguE", /* main-index: 14*/
//            "t1fNjYzExUXxwZxB8uMGt8fRYzD1UG9PzrK", /* main-index: 15*/
//            "t1b77XjiifeVX2NUD9s8SH7rAF2WsAYirws", /* main-index: 16*/
//            "t1N13KEG8izgYeW2J9mhLHLUrh5fYxPwguE", /* main-index: 17*/
//            "t1fNjYzExUXxwZxB8uMGt8fRYzD1UG9PzrK", /* main-index: 18*/
//            "t1b77XjiifeVX2NUD9s8SH7rAF2WsAYirws", /* main-index: 19*/
//            "t1N13KEG8izgYeW2J9mhLHLUrh5fYxPwguE", /* main-index: 20*/
//            "t1fNjYzExUXxwZxB8uMGt8fRYzD1UG9PzrK", /* main-index: 21*/
//            "t1b77XjiifeVX2NUD9s8SH7rAF2WsAYirws", /* main-index: 22*/
//            "t1N13KEG8izgYeW2J9mhLHLUrh5fYxPwguE", /* main-index: 23*/
//            "t1fNjYzExUXxwZxB8uMGt8fRYzD1UG9PzrK", /* main-index: 24*/
//            "t1b77XjiifeVX2NUD9s8SH7rAF2WsAYirws", /* main-index: 25*/
//            "t1N13KEG8izgYeW2J9mhLHLUrh5fYxPwguE", /* main-index: 26*/
//            "t1fNjYzExUXxwZxB8uMGt8fRYzD1UG9PzrK", /* main-index: 27*/
//            "t1b77XjiifeVX2NUD9s8SH7rAF2WsAYirws", /* main-index: 28*/
//            "t1N13KEG8izgYeW2J9mhLHLUrh5fYxPwguE", /* main-index: 29*/
//            "t1fNjYzExUXxwZxB8uMGt8fRYzD1UG9PzrK", /* main-index: 30*/
//            "t1b77XjiifeVX2NUD9s8SH7rAF2WsAYirws", /* main-index: 31*/
//            "t1N13KEG8izgYeW2J9mhLHLUrh5fYxPwguE", /* main-index: 32*/
//            "t1fNjYzExUXxwZxB8uMGt8fRYzD1UG9PzrK", /* main-index: 33*/
//            "t1b77XjiifeVX2NUD9s8SH7rAF2WsAYirws", /* main-index: 34*/
//            "t1N13KEG8izgYeW2J9mhLHLUrh5fYxPwguE", /* main-index: 35*/
//            "t1fNjYzExUXxwZxB8uMGt8fRYzD1UG9PzrK", /* main-index: 36*/
//            "t1b77XjiifeVX2NUD9s8SH7rAF2WsAYirws", /* main-index: 37*/
//            "t1N13KEG8izgYeW2J9mhLHLUrh5fYxPwguE", /* main-index: 38*/
//            "t1fNjYzExUXxwZxB8uMGt8fRYzD1UG9PzrK", /* main-index: 39*/
//            "t1b77XjiifeVX2NUD9s8SH7rAF2WsAYirws", /* main-index: 40*/
//            "t1N13KEG8izgYeW2J9mhLHLUrh5fYxPwguE", /* main-index: 41*/
//            "t1fNjYzExUXxwZxB8uMGt8fRYzD1UG9PzrK", /* main-index: 42*/
//            "t1b77XjiifeVX2NUD9s8SH7rAF2WsAYirws", /* main-index: 43*/
//            "t1N13KEG8izgYeW2J9mhLHLUrh5fYxPwguE", /* main-index: 44*/
//            "t1fNjYzExUXxwZxB8uMGt8fRYzD1UG9PzrK", /* main-index: 45*/
//            "t1b77XjiifeVX2NUD9s8SH7rAF2WsAYirws", /* main-index: 47*/

// "t3SAe5q2qTaZyFvQwGDTRLYGVtNpzhi9EyG", /* main-index: 47*/
};
        assert(vFoundersRewardAddress.size() <= consensus.GetLastFoundersRewardBlockHeight());
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        strCurrencyUnits = "TBZC";
        bip44CoinType = 1;
        consensus.fCoinbaseMustBeProtected = true;
        consensus.nSubsidySlowStartInterval = 7777;
        consensus.nSubsidyHalvingInterval = 1314001;
        consensus.nMajorityEnforceBlockUpgrade = 51;
        consensus.nMajorityRejectBlockOutdated = 75;
        consensus.nMajorityWindow = 400;
        const size_t N = 200, K = 9;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        consensus.nEquihashN = N;
        consensus.nEquihashK = K;
        consensus.powLimit = uint256S("07ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowAveragingWindow = 17;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 32; // 32% adjustment down
        consensus.nPowMaxAdjustUp = 16; // 16% adjustment up
        consensus.nPowTargetSpacing =2.5 * 60;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nActivationHeight =
            Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nProtocolVersion = 175001;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nActivationHeight = 3;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nProtocolVersion = 175001;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight = 5;
	consensus.vUpgrades[Consensus::UPGRADE_BLOSSOM].nProtocolVersion = 170008;
        consensus.vUpgrades[Consensus::UPGRADE_BLOSSOM].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;



   // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");


        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0x1a;
        pchMessageStart[2] = 0xf9;
        pchMessageStart[3] = 0xbf;
        vAlertPubKey = ParseHex("044e7a1553392325c871c5ace5d6ad73501c66f4c185d6b0453cf45dec5a1322e705c672ac1a27ef7cdaf588c10effdf50ed5f95f85f2f54a5f6159fca394ed0c6");
        nDefaultPort = 15213;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(
            1573320600,
            uint256S("0x000000000000000000000000000000000000000000000000000000000000000b"),
            ParseHex("00be48248fc56f60f7b192a2336b935545eeb67a375bcafd1a216abdb3d3e326a0595e2f1a9d17fd445a01d2a7394315545b3dc5b44fc07be875c29f0e9f9a24769f4f214a95f064cfe2c7c03b828addde9e549b01b3b8b68501f108c358f292355f5d829c5257ab8218eb1daf0e8d2f6d7c7583ffac594089d64315c70f092de782546325cb7896a19a2c6af6970115fca3d2563047a1f116bb45c033f9352b6409f65ee553fbcf057b4be198c23fc7c9850227b418659de6aa50d9ef0ec0b48f74960057de60e30eef9e4c9cf2942ba238235eaa0faaab98255e85948147a9dd72ed7dda5232668d4410ace473735383c76015f9453200f63d5bc312dc25de4d14b040b966e1f819e0ce35303c6fb52e2a98f3c913193cc7af5bd39f6264439d53819c1e5a21e59db2eb5c902eff8df93ae2541d2a65a919edb45a5b6b9714e29a5dfa5106dbdebc5ac6db03fb6ac8026215df4347ff7664f4764bd1ffadb59408d753031c8064237fa1592b5fb7c26b1eb170dd0898b89f6308d8742364667dadb665c4e9d1dd71513ee4cad517176774c74861916f4bcb737bdd7775ee4aef7517bb038f0a4bab17e2c0d9f65d7b2afdc2a77f655f1cdf0c224c818fc3aad756bfa0f37a6cb348495a93a7d1265215edb9cc4cc1ba19427b797d4cb150f39919642a846b43200cbb9fac45962968e15651bf2b912f2d030c716875d8533b7b8f64b3c378e9116fc437da1510c7d56ea34956fd601f327309b4db130867fc0e9f1a66058541b3df45f90e01ae795bd17640cd7c24422f1d8d880dd3d812b9c15a993cd6358ee6d79ebafc04020b31c2417667b6d3d3020df4af1962ba59761b26434e171666ea57ae2e06ef805f09026ae5db81b808b36f337a4f5e78a22f7195775cf5e55a4a90a021447095ff9e962fa15e940bd4fc60036b7da91ca47c01ae52b342911d31f6b030b1111ceff83366feb6f63b8a1ddef49228d56f5506f525753a1626dbfdf29904d8b747a887644bc2c5509dc1873585ab1730f02d0efd718b29ea8747a135c22751df04e4afcbe6eeb1031aa4ec960f81899346211e8cddc330f66977fdf90db4da44e11ba3a952d1aa6af36593cbbc27fe1ea4045045c2a4619887647e23e990ebffe6f4899df9fc09e0b451a28b03e875e44323efd14e810b66f7f29402e500ac6100ee815f7a606a6c8869f6c8681abc8f34b7350919d79ca3933264ef3e5e3f7654e0b67390059707acfad06581e4cda956164e939aed875a75ee0feb5c88bb0ccd086a2818eaa3e3b0eed0c25a6f57068f93579644f6f2ca09b087c315c1664f533781d61496cb94c7d76497cc1a23057e7ec7fdbb51f401670d1384163e20cfbbd22da49036ca50adb6dcfc9d9726c66f4f408c22ecffee46f351d66bfe59a6f56fad01c476aae6cd16c95f0381d3db79e54d0897115e0a13b537a90c62a7938e13b385fefd76832f885d1548277ded06b79979f9ce9507ad317f8e832ffe3abd5a42e6bccadbeaa947f6197523d32dcfd24d071cbd101f4b567bec34b183d52354efe45990ed54dacf73f32c5c5de8118fa205138114b21e77ca2e196fd9c8ff21bca2c3d76de72df4da335d683e3d6ae3ab5c38d745e1cf07429de675294ee521d9ce59e617acfd0d64043928aa2421cc4f827b01a3a44fa5c8dfaed9b44a319be2eb727336f9b0c8c6dcc3e99bb353887e4adb11ba8bf4a323b51f9fa1f5c3cf75ba05b64cb779d716bf153d538d83db2612d56b9be5d5296060f0eefa0ccc075c73c7835ecea92aebec6704eb8a2bfc6f406c84cd41d25c7d9b2c4d688233d98f936c945e09232baa82b8b7149449e27d778895663b4b9ea73daeb932ac9a2ce3dfc0c9470bf6b821fcc76e89551573c9"),
            0x2007ffff, 4, 0);
        consensus.hashGenesisBlock = genesis.GetHash();
                printf("block.nTime = %u \n", genesis.nTime);
                printf("block.nNonce = %s \n", genesis.nNonce.ToString().c_str());
                printf("block.GetHash = %s\n", genesis.GetHash().ToString().c_str());
                printf("block.merkle = %s\n", genesis.hashMerkleRoot.ToString().c_str());
        assert(consensus.hashGenesisBlock == uint256S("0x54f6493132df0fd84b9d1ab73dbd2c1e4bea7b2e5866044943839d632d8fef35"));
        assert(genesis.hashMerkleRoot == uint256S("0xe61b7d3ec8da5e04425f30cfd83e2524ad0b11d1d62bb9f0776b8372af4cc876"));

        //vFixedSeeds.clear();
        //vSeeds.clear();
        //vSeeds.push_back(CDNSSeedData("z.cash", "dnsseed.testnet.z.cash")); // Zcash

        // guarantees the first 2 characters, when base58 encoded, are "tm"
        base58Prefixes[PUBKEY_ADDRESS]     = {0x1D,0x25};
        // guarantees the first 2 characters, when base58 encoded, are "t2"
        base58Prefixes[SCRIPT_ADDRESS]     = {0x1C,0xBA};
        // the first character, when base58 encoded, is "9" or "c" (as in Bitcoin)
        base58Prefixes[SECRET_KEY]         = {0xEF};
        // do not rely on these BIP32 prefixes; they are not specified and may change
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x04,0x35,0x87,0xCF};
        base58Prefixes[EXT_SECRET_KEY]     = {0x04,0x35,0x83,0x94};
        // guarantees the first 2 characters, when base58 encoded, are "zt"
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {0x16,0xB6};
        // guarantees the first 4 characters, when base58 encoded, are "ZiVt"
        base58Prefixes[ZCVIEWING_KEY]      = {0xA8,0xAC,0x0C};
        // guarantees the first 2 characters, when base58 encoded, are "ST"
        base58Prefixes[ZCSPENDING_KEY]     = {0xAC,0x08};

        bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "ztestsapling";
        bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "zviewtestsapling";
        bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "zivktestsapling";
        bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "secret-extended-key-test";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;


        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            ( 0, consensus.hashGenesisBlock),
            genesis.nTime,
            0,
            0
            //(0, uint256S("0x0034bdd8cedc446a5f1ff2dbcf7333b499a92a21d06b247ee57fb161d7360091")),
            //(3,   uint256S("0x0614b59c26ded31075377ef3980c7db4b3a1663bab4ca96f8d525dae723cdb5a"))
            //(4,   uint256S("0x01547d1faa3fea42b0838fab3a6bc7c608a56728c9c0b95ca40a5047fbcccfb7"))
            //(5,   uint256S("0x024adc569580decf8551d3bf9275c3fa960be871cd929f63264c614ee2a6b336")),
              //1540411734,  // * UNIX timestamp of last checkpoint block
              //6,       // * total number of transactions between genesis and last checkpoint
                         //   (the tx=... number in the SetBestChain debug.log lines)
              //100           //   total number of tx / (checkpoint block height / (24 * 24))
         };

        // Founders reward script expects a vector of 2-of-3 multisig addresses
        vFoundersRewardAddress = {
//            "t2UNzUUx8mWBCRYPRezvA363EYXyEpHokyi", "t2N9PH9Wk9xjqYg9iin1Ua3aekJqfAtE543", "t2NGQjYMQhFndDHguvUw4wZdNdsssA6K7x2", "t2ENg7hHVqqs9JwU5cgjvSbxnT2a9USNfhy",
//            "t2BkYdVCHzvTJJUTx4yZB8qeegD8QsPx8bo", "t2J8q1xH1EuigJ52MfExyyjYtN3VgvshKDf", "t2Crq9mydTm37kZokC68HzT6yez3t2FBnFj", "t2EaMPUiQ1kthqcP5UEkF42CAFKJqXCkXC9",
//            "t2F9dtQc63JDDyrhnfpzvVYTJcr57MkqA12", "t2LPirmnfYSZc481GgZBa6xUGcoovfytBnC", "t26xfxoSw2UV9Pe5o3C8V4YybQD4SESfxtp", "t2D3k4fNdErd66YxtvXEdft9xuLoKD7CcVo",
//            "t2DWYBkxKNivdmsMiivNJzutaQGqmoRjRnL", "t2C3kFF9iQRxfc4B9zgbWo4dQLLqzqjpuGQ", "t2MnT5tzu9HSKcppRyUNwoTp8MUueuSGNaB", "t2AREsWdoW1F8EQYsScsjkgqobmgrkKeUkK",
//            "t2Vf4wKcJ3ZFtLj4jezUUKkwYR92BLHn5UT", "t2K3fdViH6R5tRuXLphKyoYXyZhyWGghDNY", "t2VEn3KiKyHSGyzd3nDw6ESWtaCQHwuv9WC", "t2F8XouqdNMq6zzEvxQXHV1TjwZRHwRg8gC",
//            "t2BS7Mrbaef3fA4xrmkvDisFVXVrRBnZ6Qj", "t2FuSwoLCdBVPwdZuYoHrEzxAb9qy4qjbnL", "t2SX3U8NtrT6gz5Db1AtQCSGjrpptr8JC6h", "t2V51gZNSoJ5kRL74bf9YTtbZuv8Fcqx2FH",
//            "t2FyTsLjjdm4jeVwir4xzj7FAkUidbr1b4R", "t2EYbGLekmpqHyn8UBF6kqpahrYm7D6N1Le", "t2NQTrStZHtJECNFT3dUBLYA9AErxPCmkka", "t2GSWZZJzoesYxfPTWXkFn5UaxjiYxGBU2a",
//            "t2RpffkzyLRevGM3w9aWdqMX6bd8uuAK3vn", "t2JzjoQqnuXtTGSN7k7yk5keURBGvYofh1d", "t2AEefc72ieTnsXKmgK2bZNckiwvZe3oPNL", "t2NNs3ZGZFsNj2wvmVd8BSwSfvETgiLrD8J",
//            "t2ECCQPVcxUCSSQopdNquguEPE14HsVfcUn", "t2JabDUkG8TaqVKYfqDJ3rqkVdHKp6hwXvG", "t2FGzW5Zdc8Cy98ZKmRygsVGi6oKcmYir9n", "t2DUD8a21FtEFn42oVLp5NGbogY13uyjy9t",
//            "t2UjVSd3zheHPgAkuX8WQW2CiC9xHQ8EvWp", "t2TBUAhELyHUn8i6SXYsXz5Lmy7kDzA1uT5", "t2Tz3uCyhP6eizUWDc3bGH7XUC9GQsEyQNc", "t2NysJSZtLwMLWEJ6MH3BsxRh6h27mNcsSy",
//            "t2KXJVVyyrjVxxSeazbY9ksGyft4qsXUNm9", "t2J9YYtH31cveiLZzjaE4AcuwVho6qjTNzp", "t2QgvW4sP9zaGpPMH1GRzy7cpydmuRfB4AZ", "t2NDTJP9MosKpyFPHJmfjc5pGCvAU58XGa4",
//            "t29pHDBWq7qN4EjwSEHg8wEqYe9pkmVrtRP", "t2Ez9KM8VJLuArcxuEkNRAkhNvidKkzXcjJ", "t2D5y7J5fpXajLbGrMBQkFg2mFN8fo3n8cX", "t2UV2wr1PTaUiybpkV3FdSdGxUJeZdZztyt",
            };
        assert(vFoundersRewardAddress.size() <= consensus.GetLastFoundersRewardBlockHeight());
    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        strCurrencyUnits = "REG";
        bip44CoinType = 1;
        consensus.fCoinbaseMustBeProtected = false;
        consensus.nSubsidySlowStartInterval = 0;
        consensus.nSubsidyHalvingInterval = 150;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        const size_t N = 48, K = 5;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        consensus.nEquihashN = N;
        consensus.nEquihashK = K;
        consensus.powLimit = uint256S("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
        consensus.nPowAveragingWindow = 17;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 0; // Turn off adjustment down
        consensus.nPowMaxAdjustUp = 0; // Turn off adjustment up
        consensus.nPowTargetSpacing = 2.5 * 60;
        consensus.nPowAllowMinDifficultyBlocksAfterHeight = 0;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nProtocolVersion = 170001;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nActivationHeight =
            Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nProtocolVersion = 170001;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nProtocolVersion = 170001;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nProtocolVersion = 170001;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_BLOSSOM].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::UPGRADE_BLOSSOM].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        pchMessageStart[0] = 0xaa;
        pchMessageStart[1] = 0xe7;
        pchMessageStart[2] = 0x3f;
        pchMessageStart[3] = 0x5f;
        nDefaultPort = 18734;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(
            1573320600,
            uint256S("0x000000000000000000000000000000000000000000000000000000000000000d"),
            ParseHex("0aeb92f353cd4da379233823f24269a27d45163f8fecc1d2d08f155137587fb65ec7bde1"),
            0x200f0f0f, 4, 0);
        consensus.hashGenesisBlock = genesis.GetHash();
                printf("block.nTime = %u \n", genesis.nTime);
                printf("block.nNonce = %s \n", genesis.nNonce.ToString().c_str());
                printf("block.GetHash = %s\n", genesis.GetHash().ToString().c_str());
                printf("block.merkle = %s\n", genesis.hashMerkleRoot.ToString().c_str());
        assert(consensus.hashGenesisBlock == uint256S("0xa6a00f1cad43a2ff6667d16afeb60527aaffc01deec6b93cb246ebc68cf3b378"));
        assert(genesis.hashMerkleRoot == uint256S("0xe61b7d3ec8da5e04425f30cfd83e2524ad0b11d1d62bb9f0776b8372af4cc876"));

        vFixedSeeds.clear(); //! Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();  //! Regtest mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;

        checkpointData = (CCheckpointData){
            boost::assign::map_list_of
            ( 0, uint256S("0x0d8885ee19400cb5af537d20875f4e1869fb438342464f92102cd510e25bfaea")),
            0,
            0,
            0
        };
        // These prefixes are the same as the testnet prefixes
        base58Prefixes[PUBKEY_ADDRESS]     = {0x1D,0x25};
        base58Prefixes[SCRIPT_ADDRESS]     = {0x1C,0xBA};
        base58Prefixes[SECRET_KEY]         = {0xEF};
        // do not rely on these BIP32 prefixes; they are not specified and may change
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x04,0x35,0x87,0xCF};
        base58Prefixes[EXT_SECRET_KEY]     = {0x04,0x35,0x83,0x94};
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {0x16,0xB6};
        base58Prefixes[ZCVIEWING_KEY]      = {0xA8,0xAC,0x0C};
        base58Prefixes[ZCSPENDING_KEY]     = {0xAC,0x08};

        bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "zregtestsapling";
        bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "zviewregtestsapling";
        bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "zivkregtestsapling";
        bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "secret-extended-key-regtest";

        // Founders reward script expects a vector of 2-of-3 multisig addresses
        vFoundersRewardAddress = { 
//"t2FwcEhFdNXuFMv1tcYwaBJtYVtMj8b1uTg" 
};
        assert(vFoundersRewardAddress.size() <= consensus.GetLastFoundersRewardBlockHeight());
    }

    void UpdateNetworkUpgradeParameters(Consensus::UpgradeIndex idx, int nActivationHeight)
    {
        assert(idx > Consensus::BASE_SPROUT && idx < Consensus::MAX_NETWORK_UPGRADES);
        consensus.vUpgrades[idx].nActivationHeight = nActivationHeight;
    }

    void SetRegTestZIP209Enabled() {
        fZIP209Enabled = true;
    }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams &Params(CBaseChainParams::Network network) {
    switch (network) {
        case CBaseChainParams::MAIN:
            return mainParams;
        case CBaseChainParams::TESTNET:
            return testNetParams;
        case CBaseChainParams::REGTEST:
            return regTestParams;
        default:
            assert(false && "Unimplemented network");
            return mainParams;
    }
}

void SelectParams(CBaseChainParams::Network network) {
    SelectBaseParams(network);
    pCurrentParams = &Params(network);

    // Some python qa rpc tests need to enforce the coinbase consensus rule
    if (network == CBaseChainParams::REGTEST && mapArgs.count("-regtestprotectcoinbase")) {
        regTestParams.SetRegTestCoinbaseMustBeProtected();
    }

    // When a developer is debugging turnstile violations in regtest mode, enable ZIP209
    if (network == CBaseChainParams::REGTEST && mapArgs.count("-developersetpoolsizezero")) {
        regTestParams.SetRegTestZIP209Enabled();
    }
}

bool SelectParamsFromCommandLine()
{
    CBaseChainParams::Network network = NetworkIdFromCommandLine();
    if (network == CBaseChainParams::MAX_NETWORK_TYPES)
        return false;

    SelectParams(network);
    return true;
}


// Block height must be >0 and <=last founders reward block height
// Index variable i ranges from 0 - (vFoundersRewardAddress.size()-1)
std::string CChainParams::GetFoundersRewardAddressAtHeight(int nHeight) const {
    int maxHeight = consensus.GetLastFoundersRewardBlockHeight();
    assert(nHeight > 0 && nHeight <= maxHeight);

    size_t addressChangeInterval = (maxHeight + vFoundersRewardAddress.size()) / vFoundersRewardAddress.size();
    size_t i = nHeight / addressChangeInterval;
    return vFoundersRewardAddress[i];
}

// Block height must be >0 and <=last founders reward block height
// The founders reward address is expected to be a multisig (P2SH) address
CScript CChainParams::GetFoundersRewardScriptAtHeight(int nHeight) const {
    assert(nHeight > 0 && nHeight <= consensus.GetLastFoundersRewardBlockHeight());

    CTxDestination address = DecodeDestination(GetFoundersRewardAddressAtHeight(nHeight).c_str());
    assert(IsValidDestination(address));
    assert(boost::get<CScriptID>(&address) != nullptr);
    CScriptID scriptID = boost::get<CScriptID>(address); // address is a boost variant
    CScript script = CScript() << OP_HASH160 << ToByteVector(scriptID) << OP_EQUAL;
    return script;
}

std::string CChainParams::GetFoundersRewardAddressAtIndex(int i) const {
    assert(i >= 0 && i < vFoundersRewardAddress.size());
    return vFoundersRewardAddress[i];
}

void UpdateNetworkUpgradeParameters(Consensus::UpgradeIndex idx, int nActivationHeight)
{
    regTestParams.UpdateNetworkUpgradeParameters(idx, nActivationHeight);
}
