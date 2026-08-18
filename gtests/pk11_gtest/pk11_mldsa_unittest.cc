/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <functional>
#include <string>
#include <vector>

#include "gtest/gtest.h"

#include "json_reader.h"
#include "keyhi.h"
#include "ml_dsat.h"
#include "nss_scoped_ptrs.h"
#include "pk11pub.h"
#include "prerror.h"
#include "secasn1.h"
#include "secerr.h"
#include "secitem.h"
#include "secoid.h"

namespace nss_test {

// Wycheproof ML-DSA vectors driven through PKCS#11 rather than freebl. The
// same vectors are run against freebl directly in
// gtests/freebl_gtest/mldsa_unittest.cc; here they go in as the DER encoded
// keys that the files carry, so they also cover the SubjectPublicKeyInfo and
// PKCS#8 decoders, pk11wrap and softoken.

struct MlDsaTestVector {
  uint64_t id;
  bool valid;
  std::vector<uint8_t> msg;
  std::vector<uint8_t> ctx;
  std::vector<uint8_t> sig;
  bool has_msg = false;
  bool has_rnd = false;
};

static SECItem as_item(const std::vector<uint8_t>& v) {
  SECItem item = {siBuffer, const_cast<uint8_t*>(v.data()),
                  static_cast<unsigned int>(v.size())};
  return item;
}

// Append a DER tag and length, then the value.
static void DerTlv(std::vector<uint8_t>* out, uint8_t tag, const uint8_t* value,
                   size_t len) {
  out->push_back(tag);
  if (len < 0x80) {
    out->push_back(static_cast<uint8_t>(len));
  } else if (len < 0x100) {
    out->push_back(0x81);
    out->push_back(static_cast<uint8_t>(len));
  } else {
    ASSERT_LT(len, 0x10000u);
    out->push_back(0x82);
    out->push_back(static_cast<uint8_t>(len >> 8));
    out->push_back(static_cast<uint8_t>(len));
  }
  out->insert(out->end(), value, value + len);
}

class Pkcs11MlDsaWycheproofTest : public ::testing::Test {
 protected:
  typedef std::function<void(const MlDsaTestVector&)> Operation;

  void Run(const std::string& file, SECOidTag oid, const std::string& schema,
           Operation op) {
    oid_ = oid;
    op_ = op;
    WycheproofHeader(file, ParameterSetName(oid), schema,
                     [this](JsonReader& r) { RunGroup(r); });
  }

  void Verify(const MlDsaTestVector& t) {
    ScopedSECKEYPublicKey pub(ImportPublicKey(publicKeyDer_));
    if (!pub) {
      EXPECT_FALSE(t.valid) << "could not import the public key of a valid "
                               "vector: "
                            << PORT_ErrorToString(PORT_GetError());
      return;
    }

    SECItem msg = as_item(t.msg);
    SECItem sig = as_item(t.sig);
    SECItem param = SigningParams(t.ctx);
    SECStatus rv = PK11_VerifyWithMechanism(pub.get(), CKM_ML_DSA, &param, &sig,
                                            &msg, nullptr);
    EXPECT_EQ(t.valid ? SECSuccess : SECFailure, rv);
  }

  void Sign(const MlDsaTestVector& t) {
    // Neither external-mu signing (a test case with a mu but no message) nor
    // hedged signing with caller-supplied randomness can be expressed here.
    if (!t.has_msg || t.has_rnd) {
      return;
    }

    ScopedSECKEYPrivateKey priv(ImportPrivateKey(Pkcs8()));
    if (!priv) {
      EXPECT_FALSE(t.valid) << "could not import the private key of a valid "
                               "vector: "
                            << PORT_ErrorToString(PORT_GetError());
      return;
    }

    std::vector<uint8_t> sigbuf(MAX_ML_DSA_SIGNATURE_LEN);
    SECItem sig = {siBuffer, sigbuf.data(), (unsigned int)sigbuf.size()};
    SECItem msg = as_item(t.msg);
    SECItem param = SigningParams(t.ctx);

    SECStatus rv =
        PK11_SignWithMechanism(priv.get(), CKM_ML_DSA, &param, &sig, &msg);
    ASSERT_EQ(t.valid ? SECSuccess : SECFailure, rv);
    if (!t.valid) {
      return;
    }
    EXPECT_EQ(t.sig, std::vector<uint8_t>(sig.data, sig.data + sig.len));
  }

 private:
  static std::string ParameterSetName(SECOidTag oid) {
    switch (oid) {
      case SEC_OID_ML_DSA_44:
        return "ML-DSA-44";
      case SEC_OID_ML_DSA_65:
        return "ML-DSA-65";
      case SEC_OID_ML_DSA_87:
        return "ML-DSA-87";
      default:
        ADD_FAILURE() << "unsupported parameter set";
        return "";
    }
  }

  // Deterministic signing, so that a signature can be compared against the
  // expected one. Verification ignores the hedge variant but takes the same
  // parameter structure.
  SECItem SigningParams(const std::vector<uint8_t>& ctx) {
    signCtx_.hedgeVariant = CKH_DETERMINISTIC_REQUIRED;
    signCtx_.pContext = const_cast<uint8_t*>(ctx.data());
    signCtx_.ulContextLen = ctx.size();
    SECItem param = {siBuffer, (unsigned char*)&signCtx_, sizeof(signCtx_)};
    return param;
  }

  // The signing key to import. Most groups carry a PKCS#8; the rest give only
  // a raw seed or a raw expanded key, which have to be wrapped in one.
  std::vector<uint8_t> Pkcs8() {
    if (!privateKeyPkcs8_.empty()) {
      return privateKeyPkcs8_;
    }
    if (!privateSeed_.empty()) {
      return BuildPkcs8(SEC_ASN1_CONTEXT_SPECIFIC | 0, privateSeed_);
    }
    return BuildPkcs8(SEC_ASN1_OCTET_STRING, privateKey_);
  }

  /* Wrap a raw signing key in a OneAsymmetricKey:
   *
   *   SEQUENCE {
   *     INTEGER 0,
   *     SEQUENCE { OBJECT IDENTIFIER id-ml-dsa-NN },
   *     OCTET STRING { <key> }
   *   }
   *
   * where <key> is the private key CHOICE: [0] for a seed, or an OCTET STRING
   * for an expanded key. See SECKEY_PQPrivateKey*Template and the CHOICE
   * dispatch in lib/pk11wrap/pk11pk12.c. */
  std::vector<uint8_t> BuildPkcs8(uint8_t choiceTag,
                                  const std::vector<uint8_t>& key) {
    SECOidData* oid = SECOID_FindOIDByTag(oid_);
    EXPECT_TRUE(oid);
    if (!oid) {
      return std::vector<uint8_t>();
    }

    std::vector<uint8_t> algorithm;
    DerTlv(&algorithm, SEC_ASN1_OBJECT_ID, oid->oid.data, oid->oid.len);

    std::vector<uint8_t> choice;
    DerTlv(&choice, choiceTag, key.data(), key.size());

    std::vector<uint8_t> body;
    const uint8_t version = 0;
    DerTlv(&body, SEC_ASN1_INTEGER, &version, sizeof(version));
    DerTlv(&body, SEC_ASN1_CONSTRUCTED | SEC_ASN1_SEQUENCE, algorithm.data(),
           algorithm.size());
    DerTlv(&body, SEC_ASN1_OCTET_STRING, choice.data(), choice.size());

    std::vector<uint8_t> pkcs8;
    DerTlv(&pkcs8, SEC_ASN1_CONSTRUCTED | SEC_ASN1_SEQUENCE, body.data(),
           body.size());
    return pkcs8;
  }

  ScopedSECKEYPublicKey ImportPublicKey(const std::vector<uint8_t>& spki) {
    SECItem item = as_item(spki);
    ScopedCERTSubjectPublicKeyInfo info(
        SECKEY_DecodeDERSubjectPublicKeyInfo(&item));
    if (!info) {
      return nullptr;
    }
    return ScopedSECKEYPublicKey(SECKEY_ExtractPublicKey(info.get()));
  }

  ScopedSECKEYPrivateKey ImportPrivateKey(const std::vector<uint8_t>& pkcs8) {
    ScopedPK11SlotInfo slot(PK11_GetInternalSlot());
    EXPECT_TRUE(slot);
    if (!slot || pkcs8.empty()) {
      return nullptr;
    }

    SECItem item = as_item(pkcs8);
    SECKEYPrivateKey* key = nullptr;
    if (PK11_ImportDERPrivateKeyInfoAndReturnKey(slot.get(), &item, nullptr,
                                                 nullptr, false, false, KU_ALL,
                                                 &key, nullptr) != SECSuccess) {
      return nullptr;
    }
    return ScopedSECKEYPrivateKey(key);
  }

  static void ReadTestAttr(MlDsaTestVector& t, const std::string& n,
                           JsonReader& r) {
    if (n == "msg") {
      t.msg = r.ReadHex();
      t.has_msg = true;
    } else if (n == "ctx") {
      t.ctx = r.ReadHex();
    } else if (n == "sig") {
      t.sig = r.ReadHex();
    } else if (n == "rnd") {
      r.SkipValue();
      t.has_rnd = true;
    } else if (n == "mu") {
      r.SkipValue();
    } else {
      FAIL() << "unsupported test case field: " << n;
    }
  }

  void RunGroup(JsonReader& r) {
    std::vector<MlDsaTestVector> tests;
    publicKeyDer_.clear();
    privateKeyPkcs8_.clear();
    privateKey_.clear();
    privateSeed_.clear();

    while (r.NextItem()) {
      std::string n = r.ReadLabel();
      if (n == "") {
        break;
      }
      if (n == "publicKeyDer") {
        publicKeyDer_ = r.ReadHex();
      } else if (n == "privateKeyPkcs8") {
        // Null for groups whose signing key cannot be encoded.
        privateKeyPkcs8_ = ReadOptionalHex(r);
      } else if (n == "privateKey") {
        privateKey_ = r.ReadHex();
      } else if (n == "privateSeed") {
        privateSeed_ = r.ReadHex();
      } else if (n == "type" || n == "source" || n == "publicKey") {
        // publicKey is the raw form of the key taken here as publicKeyDer.
        r.SkipValue();
      } else if (n == "tests") {
        WycheproofReadTests(r, &tests, ReadTestAttr, false);
      } else {
        FAIL() << "unknown group label: " << n;
      }
    }

    for (auto& t : tests) {
      SCOPED_TRACE(testing::Message() << "tcId " << t.id);
      op_(t);
    }
  }

  static std::vector<uint8_t> ReadOptionalHex(JsonReader& r) {
    if (r.PeekValue() == 'n') {  // null
      r.SkipValue();
      return std::vector<uint8_t>();
    }
    return r.ReadHex();
  }

  SECOidTag oid_;
  Operation op_;
  CK_SIGN_ADDITIONAL_CONTEXT signCtx_;
  std::vector<uint8_t> publicKeyDer_;
  std::vector<uint8_t> privateKeyPkcs8_;
  std::vector<uint8_t> privateKey_;
  std::vector<uint8_t> privateSeed_;
};

#define ML_DSA_WYCHEPROOF_TESTS(name, bits, oid)                             \
  TEST_F(Pkcs11MlDsaWycheproofTest, name##Verify) {                          \
    Run("mldsa_" #bits "_verify", oid, "mldsa_verify_schema.json",           \
        [this](const MlDsaTestVector& t) { Verify(t); });                    \
  }                                                                          \
  TEST_F(Pkcs11MlDsaWycheproofTest, name##SignSeed) {                        \
    Run("mldsa_" #bits "_sign_seed", oid, "mldsa_sign_seed_schema.json",     \
        [this](const MlDsaTestVector& t) { Sign(t); });                      \
  }                                                                          \
  TEST_F(Pkcs11MlDsaWycheproofTest, name##SignNoSeed) {                      \
    Run("mldsa_" #bits "_sign_noseed", oid, "mldsa_sign_noseed_schema.json", \
        [this](const MlDsaTestVector& t) { Sign(t); });                      \
  }

ML_DSA_WYCHEPROOF_TESTS(MlDsa44, 44, SEC_OID_ML_DSA_44)
ML_DSA_WYCHEPROOF_TESTS(MlDsa65, 65, SEC_OID_ML_DSA_65)
ML_DSA_WYCHEPROOF_TESTS(MlDsa87, 87, SEC_OID_ML_DSA_87)

// Lifetime tests for the MLDSAContext that softoken manages during a signing
// operation. These should be run under ASAN.
class Pkcs11MlDsaLifetimeTest : public ::testing::Test {
 protected:
  void SetUp() override {
    slot_.reset(PK11_GetInternalSlot());
    ASSERT_TRUE(slot_);

    CK_ML_DSA_PARAMETER_SET_TYPE paramSet = CKP_ML_DSA_44;
    SECKEYPublicKey* pub = nullptr;
    priv_.reset(PK11_GenerateKeyPair(slot_.get(), CKM_ML_DSA_KEY_PAIR_GEN,
                                     &paramSet, &pub, PR_FALSE, PR_FALSE,
                                     nullptr));
    pub_.reset(pub);
    ASSERT_TRUE(priv_);
    ASSERT_TRUE(pub_);

    signCtx_.hedgeVariant = CKH_DETERMINISTIC_REQUIRED;
    signCtx_.pContext = nullptr;
    signCtx_.ulContextLen = 0;
    param_.type = siBuffer;
    param_.data = (unsigned char*)&signCtx_;
    param_.len = sizeof(signCtx_);
  }

  // C_SignInit happens here, which is where softoken builds the MLDSAContext.
  PK11Context* StartSigning() {
    return PK11_CreateContextByPrivKey(CKM_ML_DSA, CKA_SIGN, priv_.get(),
                                       &param_);
  }

  static const unsigned char kMsg[6];
  ScopedPK11SlotInfo slot_;
  ScopedSECKEYPrivateKey priv_;
  ScopedSECKEYPublicKey pub_;
  CK_SIGN_ADDITIONAL_CONTEXT signCtx_;
  SECItem param_;
};

const unsigned char Pkcs11MlDsaLifetimeTest::kMsg[6] = {'m', 'l', '-',
                                                        'd', 's', 'a'};

TEST_F(Pkcs11MlDsaLifetimeTest, DestroyKeyDuringSignOperation) {
  ScopedPK11Context ctx(StartSigning());
  ASSERT_TRUE(ctx);

  ASSERT_EQ(SECSuccess, PK11_DestroyObject(slot_.get(), priv_->pkcs11ID));

  ASSERT_EQ(SECSuccess, PK11_DigestOp(ctx.get(), kMsg, sizeof(kMsg)));

  std::vector<unsigned char> sigbuf(ML_DSA_44_SIGNATURE_LEN);
  unsigned int sigLen = 0;
  ASSERT_EQ(SECSuccess,
            PK11_DigestFinal(ctx.get(), sigbuf.data(), &sigLen,
                             static_cast<unsigned int>(sigbuf.size())));
  EXPECT_EQ(static_cast<unsigned int>(ML_DSA_44_SIGNATURE_LEN), sigLen);

  SECItem sig = {siBuffer, sigbuf.data(), sigLen};
  SECItem msg = {siBuffer, const_cast<unsigned char*>(kMsg), sizeof(kMsg)};
  EXPECT_EQ(SECSuccess, PK11_VerifyWithMechanism(pub_.get(), CKM_ML_DSA,
                                                 &param_, &sig, &msg, nullptr));
}

TEST_F(Pkcs11MlDsaLifetimeTest, AbandonedSignOperationDoesNotLeak) {
  PK11Context* ctx = StartSigning();
  ASSERT_TRUE(ctx);

  ASSERT_EQ(SECSuccess, PK11_DigestOp(ctx, kMsg, sizeof(kMsg)));

  PK11_DestroyContext(ctx, PR_TRUE);
}

}  // namespace nss_test
