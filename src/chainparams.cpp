// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "key_io.h"
#include "main.h"
#include "crypto/equihash.h"

#include "util.h"
#include "utilstrencodings.h"

#include <math.h>
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

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database (and is in any case of zero value).
 *
 * >>> from pyblake2 import blake2s
 * >>> 'Zcash' + blake2s(b'The Economist 2016-10-29 Known unknown: Another crypto-currency is born. BTC#436254 0000000000000000044f321997f336d2908cf8c8d6893e88dbf067e2d949487d ETH#2521903 483039a6b6bd8bd05f0584f9a078d075e454925eb71c1f13eaff59b405a721bb DJIA close on 27 Oct 2016: 18,169.68').hexdigest()
 *
 * CBlock(hash=00040fe8, ver=4, hashPrevBlock=00000000000000, hashMerkleRoot=c4eaa5, nTime=1477641360, nBits=1f07ffff, nNonce=4695, vtx=1)
 *   CTransaction(hash=c4eaa5, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff071f0104455a6361736830623963346565663862376363343137656535303031653335303039383462366665613335363833613763616331343161303433633432303634383335643334)
 *     CTxOut(nValue=0.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: c4eaa5
 */
static CBlock CreateGenesisBlock(uint32_t nTime, const uint256& nNonce, const std::vector<unsigned char>& nSolution, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "Arrowadbf633920c0fcb066cbfdb6fd64580beea19cdb7a5a2ca8683effecec09b258";
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
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
        strCurrencyUnits = "ARW";
        bip44CoinType = 350; // As registered in https://github.com/satoshilabs/slips/blob/master/slip-0044.md
        consensus.fCoinbaseMustBeProtected = true;
        consensus.nSubsidySlowStartInterval = 0;
        consensus.nPreBlossomSubsidyHalvingInterval = 2803200;
        consensus.nPostBlossomSubsidyHalvingInterval = 2803200;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 4000;
        const size_t N = 192, K = 7;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        consensus.nEquihashN = N;
        consensus.nEquihashK = K;
        consensus.powLimit = uint256S("0007ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowAveragingWindow = 17;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 32; // 32% adjustment down
        consensus.nPowMaxAdjustUp = 16; // 16% adjustment up
        consensus.nPreBlossomPowTargetSpacing = 45;
        consensus.nPostBlossomPowTargetSpacing = 45;
        // 174720 blocks/quarter
        consensus.rewardSteps = {
          {int64_t(174720 * 1), 0},
          {int64_t(174720 * 2), 15},
          {int64_t(174720 * 3), 5},
          {int64_t(174720 * 4), 5},
          {int64_t(174720 * 5), 5},
          {int64_t(174720 * 6), 5},
          {int64_t(174720 * 7), 5}
        };
        consensus.nPowAllowMinDifficultyBlocksAfterHeight = boost::none;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nProtocolVersion = 170003;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nActivationHeight =
            Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nProtocolVersion = 170007;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight =
            Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_BLOSSOM].nProtocolVersion = 170008;
        consensus.vUpgrades[Consensus::UPGRADE_BLOSSOM].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000000000001");

        /**
         * The message start string should be awesome! ➢☜ (27a2261c)
         */
        pchMessageStart[0] = 0x27;
        pchMessageStart[1] = 0xa2;
        pchMessageStart[2] = 0x26;
        pchMessageStart[3] = 0x1c;
        vAlertPubKey = ParseHex("04b7ecf0baa90495ceb4e4090f6b2fd37eec1e9c85fac68a487f3ce11589692e4a317479316ee814e066638e1db54e37a10689b70286e6315b1087b6615d179264");
        nDefaultPort = 7654;
        nPruneAfterHeight = 100000;

        genesis = CreateGenesisBlock(
            1562519857,
            uint256S("0000000000000000000000000000000000000000000000000000000000002c19"),
            ParseHex("00b41c5d3fee273b40974b44c6e903ff3733ce087e7389a925154a9e6ed1bf9bd5baf69d29526c40d688bfb705b8d5bea9f70ca0c7beddece347305899eef338ad0a66764124bddfe4c71a0fdf9f79b1eed7cc0ad178fd1658e8a4157c5f1da36fcd6e28042b06dd75afcc11ee151f5443d5ddfc4a56adce87c78646c629cc1cfc48ba1de50a3c9f0176073003d24275c9c55ff0015c29b59a2776e50f3fe792ee77d57b6eccb4b9bf2f4ebdd5ebac3601c2a5a39952dda211958197b989bfb0d4b24cfdbffbc7ad025293dfb85adefce5b3764c3589541f92097f20bc5ba93e231ce7b08f4d8f8da56edd242c79668bd72803871bd5719d9a11264734bf1a9e8e059334ff41f6b8d12b7ac8a9decbc9b57d992a15bea49bb32aa59e59a4e4f399cf82470c95ae50fb8992f90c84d64a8e85036ae2530779791b994f78a16f10a16dc0564c1600fd49a9ec8790169bf19ab2b5248b11dd0663a1c9fc7d0c218726bfe406f69149bccebd63a22ebe169c320bebdf65d6f24502cbea7bd822ef2dd594a4d6cca0e675d3de88e9779c6eb1"),
            0x1f07ffff, 4, 0);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x00028de97cd7b8e1b90918186387c0e6b9f65ac433bdde036aa93e184593da4e"));
        assert(genesis.hashMerkleRoot == uint256S("0x2318b72b4e35d86f0c66c8c956fe7c3ae1ef7c33b835c58fdd9a1ed5f2b4852a"));

        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.push_back(CDNSSeedData("mainnet1", "18.204.209.173")); // Arrow
        vSeeds.push_back(CDNSSeedData("mainnet2", "52.90.76.26")); // Arrow

        // guarantees the first 2 characters, when base58 encoded, are "ar"
        base58Prefixes[PUBKEY_ADDRESS]     = {0x13,0x0f};
        // guarantees the first 2 characters, when base58 encoded, are "aw"
        base58Prefixes[SCRIPT_ADDRESS]     = {0x13,0x1b};
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

        bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "as";
        bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "aviews";
        bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "aivks";
        bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "secret-extended-key-main";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = false;

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            (0, consensus.hashGenesisBlock)
            (3000, uint256S("0x000000584d0af0f41b7d309edb26d3cb92b1adb080811145b72d660af1bad8c6")),
            1562689693,  // * UNIX timestamp of last checkpoint block
            4333,       // * total number of transactions between genesis and last checkpoint
                         //   (the tx=... number in the SetBestChain debug.log lines)
            5760          //   total number of tx / (checkpoint block height / (24 * 24))
        };

        // Hardcoded fallback value for the Sprout shielded value pool balance
        // for nodes that have not reindexed since the introduction of monitoring
        // in #2795.
        nSproutValuePoolCheckpointHeight = 520633;
        nSproutValuePoolCheckpointBalance = 22145062442933;
        fZIP209Enabled = false;
        hashSproutValuePoolCheckpointBlock = uint256S("0000000000c7b46b6bc04b4cbf87d8bb08722aebd51232619b214f7273f8460e");

        // Founders reward script expects a vector of 2-of-3 multisig addresses
        vFoundersRewardAddress = {
          "awGmPHrdDEoR94moWqgkCgoftqVnxmSU8TW", /* Founder 1 */
          "awKh816Uu7SknBiRUqpEhAmzLgCfRMwToob", /* Founder 2 */
          "awHTq3WV9jwa7GnwFUex29Do2dxNEkpHrR4", /* Founder 3 */
          "aw9y6sA7TfnLfBcE7QdJED5jL4BRL7xnPi6", /* Founder 4 */
          "aw3PJCcQPHKzYbVpVSc4ka4MnRqdDbmvvbL", /* Founder 5 */
          "awLTtMyrwZXXZ592xJtmtDegCe56zxhMDAv", /* Founder 6 */
          "aw8Rtid3iKpCxyXCJ9ugGGVpuuSr18qpR6d", /* Founder 7 */
          "awDitPs5DiuGQo4Nzsws5Hk7ugX6YjQ52km", /* Founder 8 */
        };

        vFoundersRewardReplacementAddress = {
          {"aw8MnQYsjxnfevUQKuGYhteZ1WoGWsk3VkA", (174720 * 2), 4}
        };

        assert(vFoundersRewardAddress.size() <= consensus.GetLastFoundersRewardBlockHeight(0));
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
        strCurrencyUnits = "TAR";
        bip44CoinType = 1;
        consensus.fCoinbaseMustBeProtected = true;
        consensus.nSubsidySlowStartInterval = 0;
        consensus.nPreBlossomSubsidyHalvingInterval = 2803200;
        consensus.nPostBlossomSubsidyHalvingInterval = 2803200;
        consensus.nMajorityEnforceBlockUpgrade = 51;
        consensus.nMajorityRejectBlockOutdated = 75;
        consensus.nMajorityWindow = 400;
        const size_t N = 192, K = 7;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        consensus.nEquihashN = N;
        consensus.nEquihashK = K;
        consensus.powLimit = uint256S("07ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowAveragingWindow = 17;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 32; // 32% adjustment down
        consensus.nPowMaxAdjustUp = 16; // 16% adjustment up
        consensus.nPreBlossomPowTargetSpacing = 45;
        consensus.nPostBlossomPowTargetSpacing = 45;
        consensus.rewardSteps = {
          {int64_t(1600), 5},
          {int64_t(1700), 5},
          {int64_t(1800), 5},
          {int64_t(4000), 1},
          {int64_t(8000), 1},
          {int64_t(12000), 1},
          {int64_t(16000), 1},
          {int64_t(20000), 1},
          {int64_t(24000), 1},
          {int64_t(28000), 1},
          {int64_t(32000), 1},
          {int64_t(36000), 1},
          {int64_t(40000), 1}
        };
        consensus.nPowAllowMinDifficultyBlocksAfterHeight = 299187;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nProtocolVersion = 170003;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nActivationHeight =
            Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nProtocolVersion = 170007;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight =
            Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_BLOSSOM].nProtocolVersion = 170008;
        consensus.vUpgrades[Consensus::UPGRADE_BLOSSOM].nActivationHeight = 584000;
        consensus.vUpgrades[Consensus::UPGRADE_BLOSSOM].hashActivationBlock =
            uint256S("00367515ef2e781b8c9358b443b6329572599edd02c59e8af67db9785122f298");

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000000000001");

        pchMessageStart[0] = 0x26;
        pchMessageStart[1] = 0x1c;
        pchMessageStart[2] = 0x27;
        pchMessageStart[3] = 0xa2;
        vAlertPubKey = ParseHex("044e7a1553392325c871c5ace5d6ad73501c66f4c185d6b0453cf45dec5a1322e705c672ac1a27ef7cdaf588c10effdf50ed5f95f85f2f54a5f6159fca394ed0c6");
        nDefaultPort = 17654;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(
            1562480347,
            uint256S("00000000000000000000000000000000000000000000000000000000000018a3"),
            ParseHex("007fc5f19e248165d64e1f01b0181a95fc0c51b0e8c1e91ed50aa0d10f1e26afe14bbf1a59f487fd2a8f290a063fe9d3f29c23f99f3d89550ce2edd4d817d96e763644c2e6c29d3d92d3a9253ad446060754193f7ddb79273332af9f2e6604301f961393029c36dbf1d953fd3ff9aab84629f90f3ee555d8ad4d9b377b16556928cb8b6c35fbbc2d5bd55756ff22480198cfa329374a031176582958c544bd5fae41d1c9037a511ec5d98931eb275733c6eac4ee174fad9db90e6a460a5a841840863b8d4b5169d605fea531f88659dae53be415c9719c16d094e6e326f5a4a3d51fe6b14d031f49022a5cb040356720a6d0de6561da09e24a1707abec0ded44e44fd1bec48cd15f4592ec6092a2746199aff21df66539820b3b579b9fee75976c8876d0da8309b97ddd6c6306e8239096bb02085e5b281110770d065ba4e5edb9bf67a5ae0d87663a99fda794f21b2d16e7af00a504f412353363e6b09c161259585187d76cc6ce7170219f588e4e4c5eed5ea1b1128c1fd0f89a3ea254e373d5852dc65e22776eac8a170ccf94e7f1"),
            0x1f07ffff, 4, 0);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x000546eeffe7cc9daa9e69a21d1b0ee50953748a4d788f690de9ecff4494b838"));
        assert(genesis.hashMerkleRoot == uint256S("0x2318b72b4e35d86f0c66c8c956fe7c3ae1ef7c33b835c58fdd9a1ed5f2b4852a"));

        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.push_back(CDNSSeedData("testnet1", "18.204.209.173")); // Arrow

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

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;


        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            (0, consensus.hashGenesisBlock),
            1562480347,  // * UNIX timestamp of last checkpoint block
            1,       // * total number of transactions between genesis and last checkpoint
                         //   (the tx=... number in the SetBestChain debug.log lines)
            1          //   total number of tx / (checkpoint block height / (24 * 24))
        };

        // Hardcoded fallback value for the Sprout shielded value pool balance
        // for nodes that have not reindexed since the introduction of monitoring
        // in #2795.
        nSproutValuePoolCheckpointHeight = 440329;
        nSproutValuePoolCheckpointBalance = 40000029096803;
        fZIP209Enabled = false;
        hashSproutValuePoolCheckpointBlock = uint256S("000a95d08ba5dcbabe881fc6471d11807bcca7df5f1795c99f3ec4580db4279b");

        // Founders reward script expects a vector of 2-of-3 multisig addresses
        vFoundersRewardAddress = {
            "t2EwvMEauft1w621d7cwEUZyhR2Qg6hC69j", "t2Cz8nFidjJhMqoWzEawFBtjQBH3CAGASfn", "t2BKkVteoxfy1hHzEfs7Kqz4jUg68XkYjeG", "t2BnomTFHZ72LWBykWzCEFExEJecF1Por5j",
        };
        vFoundersRewardReplacementAddress = {
          {"t2QpsQKSEzr39jGT2Kqy9kZrSTJs4rp16tg", (3700), 1}
        };
        assert(vFoundersRewardAddress.size() <= consensus.GetLastFoundersRewardBlockHeight(0));
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
        consensus.nPreBlossomSubsidyHalvingInterval = Consensus::PRE_BLOSSOM_REGTEST_HALVING_INTERVAL;
        consensus.nPostBlossomSubsidyHalvingInterval = Consensus::POST_BLOSSOM_REGTEST_HALVING_INTERVAL;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        const size_t N = 192, K = 7;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        consensus.nEquihashN = N;
        consensus.nEquihashK = K;
        consensus.powLimit = uint256S("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
        consensus.nPowAveragingWindow = 17;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 0; // Turn off adjustment down
        consensus.nPowMaxAdjustUp = 0; // Turn off adjustment up
        consensus.nPreBlossomPowTargetSpacing = 45;
        consensus.nPostBlossomPowTargetSpacing = 45;
        consensus.rewardSteps = {
          {int64_t(1600), 5},
          {int64_t(1700), 5},
          {int64_t(1800), 5}
        };
        consensus.rewardSteps.emplace_back(int64_t(1600), 5);
        consensus.rewardSteps.emplace_back(int64_t(1700), 5);
        consensus.rewardSteps.emplace_back(int64_t(1800), 5);
        consensus.nPowAllowMinDifficultyBlocksAfterHeight = 0;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nActivationHeight =
            Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nProtocolVersion = 170003;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nProtocolVersion = 170006;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_BLOSSOM].nProtocolVersion = 170008;
        consensus.vUpgrades[Consensus::UPGRADE_BLOSSOM].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        pchMessageStart[0] = 0xaa;
        pchMessageStart[1] = 0xe8;
        pchMessageStart[2] = 0x3f;
        pchMessageStart[3] = 0x5f;
        nDefaultPort = 18344;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(
            1562480347,
            uint256S("00000000000000000000000000000000000000000000000000000000000018a3"),
            ParseHex("007fc5f19e248165d64e1f01b0181a95fc0c51b0e8c1e91ed50aa0d10f1e26afe14bbf1a59f487fd2a8f290a063fe9d3f29c23f99f3d89550ce2edd4d817d96e763644c2e6c29d3d92d3a9253ad446060754193f7ddb79273332af9f2e6604301f961393029c36dbf1d953fd3ff9aab84629f90f3ee555d8ad4d9b377b16556928cb8b6c35fbbc2d5bd55756ff22480198cfa329374a031176582958c544bd5fae41d1c9037a511ec5d98931eb275733c6eac4ee174fad9db90e6a460a5a841840863b8d4b5169d605fea531f88659dae53be415c9719c16d094e6e326f5a4a3d51fe6b14d031f49022a5cb040356720a6d0de6561da09e24a1707abec0ded44e44fd1bec48cd15f4592ec6092a2746199aff21df66539820b3b579b9fee75976c8876d0da8309b97ddd6c6306e8239096bb02085e5b281110770d065ba4e5edb9bf67a5ae0d87663a99fda794f21b2d16e7af00a504f412353363e6b09c161259585187d76cc6ce7170219f588e4e4c5eed5ea1b1128c1fd0f89a3ea254e373d5852dc65e22776eac8a170ccf94e7f1"),
            0x1f07ffff, 4, 0);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x000546eeffe7cc9daa9e69a21d1b0ee50953748a4d788f690de9ecff4494b838"));
        assert(genesis.hashMerkleRoot == uint256S("0x2318b72b4e35d86f0c66c8c956fe7c3ae1ef7c33b835c58fdd9a1ed5f2b4852a"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;

        checkpointData = (CCheckpointData){
            boost::assign::map_list_of
            ( 0, uint256S("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206")),
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
        vFoundersRewardAddress = { "t2FwcEhFdNXuFMv1tcYwaBJtYVtMj8b1uTg" };
        vFoundersRewardReplacementAddress = {
          {"aw8MnQYsjxnfevUQKuGYhteZ1WoGWsk3VkA", (10000), 0}
        };
        assert(vFoundersRewardAddress.size() <= consensus.GetLastFoundersRewardBlockHeight(0));
    }

    void UpdateNetworkUpgradeParameters(Consensus::UpgradeIndex idx, int nActivationHeight)
    {
        assert(idx > Consensus::BASE_SPROUT && idx < Consensus::MAX_NETWORK_UPGRADES);
        consensus.vUpgrades[idx].nActivationHeight = nActivationHeight;
    }

    void UpdateRegtestPow(int64_t nPowMaxAdjustDown, int64_t nPowMaxAdjustUp, uint256 powLimit)
    {
        consensus.nPowMaxAdjustDown = nPowMaxAdjustDown;
        consensus.nPowMaxAdjustUp = nPowMaxAdjustUp;
        consensus.powLimit = powLimit;
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
std::string CChainParams::GetFoundersRewardAddressAtHeight(int nHeight) const {
  int maxHeight = consensus.GetLastFoundersRewardBlockHeight(0);
  assert(nHeight > 0 && nHeight <= maxHeight);
  int i = nHeight;
  if (nHeight >= vFoundersRewardAddress.size()) {
    double mod = nHeight / vFoundersRewardAddress.size();
    i = nHeight % (int)mod;
  }
  std::string addr = vFoundersRewardAddress[i];
  // replace any addresses that need to be replaced
  if (nHeight > vFoundersRewardReplacementAddress[0].nHeight) {
    for (unsigned int j = 0; j < vFoundersRewardReplacementAddress.size(); j++) {
      if (
        (nHeight > vFoundersRewardReplacementAddress[j].nHeight) &&
        (i == vFoundersRewardReplacementAddress[j].index)
      ) {
        if (j > vFoundersRewardReplacementAddress.size() -1) {
          LogPrintf("GetFoundersRewardAddressAtHeight: replacement address index out of bounds\n");
          return "";
        }
        addr = vFoundersRewardReplacementAddress[j].address;
      }
    }
  }

  return addr;
}

// Block height must be >0 and <=last founders reward block height
// The founders reward address is expected to be a multisig (P2SH) address
CScript CChainParams::GetFoundersRewardScriptAtHeight(int nHeight) const {
    assert(nHeight > 0 && nHeight <= consensus.GetLastFoundersRewardBlockHeight(nHeight));

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

void UpdateRegtestPow(int64_t nPowMaxAdjustDown, int64_t nPowMaxAdjustUp, uint256 powLimit) {
    regTestParams.UpdateRegtestPow(nPowMaxAdjustDown, nPowMaxAdjustUp, powLimit);
}
