/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <vector>

#include "gtest/gtest.h"

#include "ml_dsat.h"
#include "nss_scoped_ptrs.h"
#include "pk11pub.h"
#include "secitem.h"

namespace nss_test {

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
