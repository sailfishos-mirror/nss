// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "gtest/gtest.h"

#include "blapi.h"
#include "secerr.h"
#include "secitem.h"

#include "kat/mldsa_keygen.h"

namespace nss_test {

static std::vector<uint8_t> from_hex(const std::string& hex) {
  EXPECT_EQ(0U, hex.size() % 2);
  std::vector<uint8_t> out(hex.size() / 2);
  for (size_t i = 0; i < out.size(); ++i) {
    out[i] =
        static_cast<uint8_t>(strtol(hex.substr(2 * i, 2).c_str(), nullptr, 16));
  }
  return out;
}

static unsigned int sig_len(CK_ML_DSA_PARAMETER_SET_TYPE p) {
  switch (p) {
    case CKP_ML_DSA_44:
      return ML_DSA_44_SIGNATURE_LEN;
    case CKP_ML_DSA_65:
      return ML_DSA_65_SIGNATURE_LEN;
    case CKP_ML_DSA_87:
      return ML_DSA_87_SIGNATURE_LEN;
  }
  return 0;
}

// Sign a message (possibly in two chunks) via the streaming freebl interface.
static SECStatus do_sign(MLDSAPrivateKey* priv, CK_HEDGE_TYPE hedge,
                         const SECItem* ctx, const SECItem* part1,
                         const SECItem* part2, SECItem* sig) {
  MLDSAContext* mctx = nullptr;
  if (MLDSA_SignInit(priv, hedge, ctx, &mctx) != SECSuccess) {
    return SECFailure;
  }
  if (part1) MLDSA_SignUpdate(mctx, part1);
  if (part2) MLDSA_SignUpdate(mctx, part2);
  return MLDSA_SignFinal(mctx, sig);  // frees mctx
}

static SECStatus do_verify(MLDSAPublicKey* pub, const SECItem* ctx,
                           const SECItem* part1, const SECItem* part2,
                           const SECItem* sig) {
  MLDSAContext* mctx = nullptr;
  if (MLDSA_VerifyInit(pub, ctx, &mctx) != SECSuccess) {
    return SECFailure;
  }
  if (part1) MLDSA_VerifyUpdate(mctx, part1);
  if (part2) MLDSA_VerifyUpdate(mctx, part2);
  return MLDSA_VerifyFinal(mctx, sig);  // frees mctx
}

class MlDsaSelfTest
    : public ::testing::TestWithParam<CK_ML_DSA_PARAMETER_SET_TYPE> {};

TEST_P(MlDsaSelfTest, SignVerifyRoundTrip) {
  CK_ML_DSA_PARAMETER_SET_TYPE param = GetParam();

  MLDSAPrivateKey priv = {};
  MLDSAPublicKey pub = {};
  ASSERT_EQ(SECSuccess, MLDSA_NewKey(param, nullptr, &priv, &pub));
  EXPECT_EQ(param, priv.paramSet);
  EXPECT_EQ(param, pub.paramSet);
  EXPECT_EQ(ML_DSA_SEED_LEN, priv.seedLen);

  uint8_t ctxbuf[] = {1, 2, 3};
  SECItem context = {siBuffer, ctxbuf, sizeof(ctxbuf)};
  std::vector<uint8_t> m1 = {'m', 'l', '-'};
  std::vector<uint8_t> m2 = {'d', 's', 'a', '!'};
  SECItem d1 = {siBuffer, m1.data(), (unsigned int)m1.size()};
  SECItem d2 = {siBuffer, m2.data(), (unsigned int)m2.size()};

  std::vector<uint8_t> sigbuf(MAX_ML_DSA_SIGNATURE_LEN);

  for (CK_HEDGE_TYPE hedge :
       {CKH_DETERMINISTIC_REQUIRED, CKH_HEDGE_PREFERRED, CKH_HEDGE_REQUIRED}) {
    SECItem sig = {siBuffer, sigbuf.data(), (unsigned int)sigbuf.size()};
    ASSERT_EQ(SECSuccess, do_sign(&priv, hedge, &context, &d1, &d2, &sig))
        << "sign hedge=" << hedge;
    EXPECT_EQ(sig_len(param), sig.len);

    // Valid signature verifies.
    EXPECT_EQ(SECSuccess, do_verify(&pub, &context, &d1, &d2, &sig));

    // Tampered message fails.
    std::vector<uint8_t> bad = {'X', 'l', '-'};
    SECItem badItem = {siBuffer, bad.data(), (unsigned int)bad.size()};
    EXPECT_EQ(SECFailure, do_verify(&pub, &context, &badItem, &d2, &sig));

    // Wrong context fails.
    uint8_t ctxbuf2[] = {9, 9, 9};
    SECItem context2 = {siBuffer, ctxbuf2, sizeof(ctxbuf2)};
    EXPECT_EQ(SECFailure, do_verify(&pub, &context2, &d1, &d2, &sig));
  }
}

// Deterministic signatures are reproducible; hedged ones differ.
TEST_P(MlDsaSelfTest, DeterministicIsStable) {
  CK_ML_DSA_PARAMETER_SET_TYPE param = GetParam();
  MLDSAPrivateKey priv = {};
  MLDSAPublicKey pub = {};
  ASSERT_EQ(SECSuccess, MLDSA_NewKey(param, nullptr, &priv, &pub));

  std::vector<uint8_t> m = {'a', 'b', 'c'};
  SECItem msg = {siBuffer, m.data(), (unsigned int)m.size()};
  SECItem emptyCtx = {siBuffer, nullptr, 0};

  std::vector<uint8_t> buf1(MAX_ML_DSA_SIGNATURE_LEN);
  std::vector<uint8_t> buf2(MAX_ML_DSA_SIGNATURE_LEN);
  SECItem s1 = {siBuffer, buf1.data(), (unsigned int)buf1.size()};
  SECItem s2 = {siBuffer, buf2.data(), (unsigned int)buf2.size()};
  ASSERT_EQ(SECSuccess, do_sign(&priv, CKH_DETERMINISTIC_REQUIRED, &emptyCtx,
                                &msg, nullptr, &s1));
  ASSERT_EQ(SECSuccess, do_sign(&priv, CKH_DETERMINISTIC_REQUIRED, &emptyCtx,
                                &msg, nullptr, &s2));
  ASSERT_EQ(s1.len, s2.len);
  EXPECT_EQ(0, memcmp(s1.data, s2.data, s1.len));
}

INSTANTIATE_TEST_SUITE_P(MlDsaSelfTest, MlDsaSelfTest,
                         ::testing::Values(CKP_ML_DSA_44, CKP_ML_DSA_65,
                                           CKP_ML_DSA_87));

// Key generation known-answer tests: deriving from the seed must reproduce the
// FIPS-204 verification and signing keys, checked via their SHA3-256 digests.
class MlDsaKeygenKatTest : public ::testing::TestWithParam<MlDsaKeygenKat> {};

TEST_P(MlDsaKeygenKatTest, Keygen) {
  const MlDsaKeygenKat& kat = GetParam();
  std::vector<uint8_t> seed = from_hex(kat.seed);
  ASSERT_EQ(ML_DSA_SEED_LEN, seed.size());

  MLDSAPrivateKey priv = {};
  MLDSAPublicKey pub = {};
  SECItem seedItem = {siBuffer, seed.data(), (unsigned int)seed.size()};
  ASSERT_EQ(SECSuccess, MLDSA_NewKey(kat.paramSet, &seedItem, &priv, &pub));

  uint8_t digest[SHA3_256_LENGTH];
  std::vector<uint8_t> expectedVk = from_hex(kat.vk_sha3_256);
  std::vector<uint8_t> expectedSk = from_hex(kat.sk_sha3_256);

  ASSERT_EQ(SECSuccess, SHA3_256_HashBuf(digest, pub.keyVal, pub.keyValLen));
  EXPECT_EQ(0, memcmp(digest, expectedVk.data(), SHA3_256_LENGTH))
      << "verification key digest mismatch";

  ASSERT_EQ(SECSuccess, SHA3_256_HashBuf(digest, priv.keyVal, priv.keyValLen));
  EXPECT_EQ(0, memcmp(digest, expectedSk.data(), SHA3_256_LENGTH))
      << "signing key digest mismatch";
}

INSTANTIATE_TEST_SUITE_P(MlDsaKeygenKatTest, MlDsaKeygenKatTest,
                         ::testing::ValuesIn(kMlDsaKeygenKats));

}  // namespace nss_test
