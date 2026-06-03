/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdlib.h>

#include "nss.h"
#include "pk11pub.h"
#include "prenv.h"
#include "prerror.h"
#include "secerr.h"
#include "secmod.h"

#include "nss_scoped_ptrs.h"
#include "gtest/gtest.h"

namespace nss_test {

// Matches the auth-required slot in pkcs11testmodule.cpp.
static const char kAuthTokenName[] = "Test PKCS11 Auth Token";
static const char kInitialSoPin[] = "0000";
static const char kModuleName[] = "Pkcs11AuthTest";

// PR_SetEnv strings (must have static storage). An empty value reads as unset
// (NSS_FORCE_TOKEN_LOCK is treated as set only when non-empty; see pk11load.c).
static const char kForceLockOn[] = "NSS_FORCE_TOKEN_LOCK=1";
static const char kForceLockOff[] = "NSS_FORCE_TOKEN_LOCK=";

// Parameter controls whether the module is loaded as non-thread-safe.
// Both variants exercise the same NSS auth APIs so regressions in either
// lock path (thread-safe slot with defRWSession, or shared module lock for
// non-thread-safe slots) are caught.
class Pkcs11AuthTest : public ::testing::TestWithParam<bool> {
 protected:
  bool ForceLock() const { return GetParam(); }

  void SetUp() override {
    // NSS_FORCE_TOKEN_LOCK must be set before SECMOD_AddNewModule, which reads
    // it at load time. Use PR_SetEnv for portability (setenv/unsetenv don't
    // exist on Windows). Clear it again afterward (empty == unset) so unrelated
    // modules loaded later aren't forced to lock.
    PR_SetEnv(ForceLock() ? kForceLockOn : kForceLockOff);
    ASSERT_EQ(SECSuccess, SECMOD_AddNewModule(
                              kModuleName,
                              DLL_PREFIX "pkcs11testmodule." DLL_SUFFIX, 0, 0))
        << PORT_ErrorToName(PORT_GetError());
    PR_SetEnv(kForceLockOff);
    slot_.reset(PK11_FindSlotByName(kAuthTokenName));
    ASSERT_NE(nullptr, slot_) << "auth token not found";
    // Confirm NSS_FORCE_TOKEN_LOCK actually produced the slot mode we want.
    ScopedSECMODModule mod(SECMOD_FindModule(kModuleName));
    ASSERT_NE(nullptr, mod);
    ASSERT_EQ(ForceLock() ? PR_FALSE : PR_TRUE, mod->isThreadSafe);
  }

  void TearDown() override {
    slot_.reset();
    int type;
    ASSERT_EQ(SECSuccess, SECMOD_DeleteModule(kModuleName, &type));
  }

  ScopedPK11SlotInfo slot_;
};

TEST_P(Pkcs11AuthTest, InitialStateNeedsUserInit) {
  EXPECT_TRUE(PK11_NeedUserInit(slot_.get()));
  EXPECT_FALSE(PK11_IsLoggedIn(slot_.get(), nullptr));
}

TEST_P(Pkcs11AuthTest, InitPinSucceedsAndLogsIn) {
  EXPECT_EQ(SECSuccess, PK11_InitPin(slot_.get(), kInitialSoPin, "1234"));
  EXPECT_FALSE(PK11_NeedUserInit(slot_.get()));
  EXPECT_TRUE(PK11_IsLoggedIn(slot_.get(), nullptr));
}

TEST_P(Pkcs11AuthTest, InitPinWrongSoPinFails) {
  EXPECT_EQ(SECFailure, PK11_InitPin(slot_.get(), "wrong", "1234"));
  EXPECT_TRUE(PK11_NeedUserInit(slot_.get()));
}

TEST_P(Pkcs11AuthTest, LogoutClearsLoginState) {
  ASSERT_EQ(SECSuccess, PK11_InitPin(slot_.get(), kInitialSoPin, "1234"));
  ASSERT_TRUE(PK11_IsLoggedIn(slot_.get(), nullptr));
  EXPECT_EQ(SECSuccess, PK11_Logout(slot_.get()));
  EXPECT_FALSE(PK11_IsLoggedIn(slot_.get(), nullptr));
}

TEST_P(Pkcs11AuthTest, CheckUserPasswordCorrect) {
  ASSERT_EQ(SECSuccess, PK11_InitPin(slot_.get(), kInitialSoPin, "1234"));
  ASSERT_EQ(SECSuccess, PK11_Logout(slot_.get()));
  EXPECT_EQ(SECSuccess, PK11_CheckUserPassword(slot_.get(), "1234"));
  EXPECT_TRUE(PK11_IsLoggedIn(slot_.get(), nullptr));
}

TEST_P(Pkcs11AuthTest, CheckUserPasswordWrong) {
  ASSERT_EQ(SECSuccess, PK11_InitPin(slot_.get(), kInitialSoPin, "1234"));
  ASSERT_EQ(SECSuccess, PK11_Logout(slot_.get()));
  EXPECT_EQ(SECWouldBlock, PK11_CheckUserPassword(slot_.get(), "wrong"));
  EXPECT_FALSE(PK11_IsLoggedIn(slot_.get(), nullptr));
}

// These differ from the user-PIN tests in two ways. First, there's no
// PK11_InitPin step: PK11_CheckSSOPassword verifies the Security Officer PIN,
// which the token has from the start ("0000" here), rather than the user PIN
// that PK11_InitPin establishes. Second, the PIN is copied into a local buffer
// because PK11_CheckSSOPassword takes a non-const char* (a string literal can't
// be passed directly).
TEST_P(Pkcs11AuthTest, CheckSSOPasswordCorrect) {
  char pin[] = "0000";
  EXPECT_EQ(SECSuccess, PK11_CheckSSOPassword(slot_.get(), pin));
}

TEST_P(Pkcs11AuthTest, CheckSSOPasswordWrong) {
  char pin[] = "wrong";
  EXPECT_EQ(SECWouldBlock, PK11_CheckSSOPassword(slot_.get(), pin));
}

TEST_P(Pkcs11AuthTest, ChangePWUpdatesUserPin) {
  ASSERT_EQ(SECSuccess, PK11_InitPin(slot_.get(), kInitialSoPin, "1234"));
  ASSERT_EQ(SECSuccess, PK11_Logout(slot_.get()));
  EXPECT_EQ(SECSuccess, PK11_ChangePW(slot_.get(), "1234", "5678"));
  EXPECT_EQ(SECWouldBlock, PK11_CheckUserPassword(slot_.get(), "1234"));
  ASSERT_EQ(SECSuccess, PK11_Logout(slot_.get()));
  EXPECT_EQ(SECSuccess, PK11_CheckUserPassword(slot_.get(), "5678"));
}

TEST_P(Pkcs11AuthTest, ChangePWWrongOldPinFails) {
  ASSERT_EQ(SECSuccess, PK11_InitPin(slot_.get(), kInitialSoPin, "1234"));
  ASSERT_EQ(SECSuccess, PK11_Logout(slot_.get()));
  EXPECT_EQ(SECFailure, PK11_ChangePW(slot_.get(), "wrong", "5678"));
  EXPECT_EQ(SECSuccess, PK11_CheckUserPassword(slot_.get(), "1234"));
}

// Drives PK11_DoPassword through PK11_Authenticate using a getPass callback.
static int doPasswordCallbackCount = 0;
static char* doPasswordCallback(PK11SlotInfo*, PRBool retry, void*) {
  doPasswordCallbackCount++;
  if (retry) return nullptr;  // refuse retry to keep test deterministic
  return PORT_Strdup("1234");
}

TEST_P(Pkcs11AuthTest, DoPasswordViaCallback) {
  ASSERT_EQ(SECSuccess, PK11_InitPin(slot_.get(), kInitialSoPin, "1234"));
  ASSERT_EQ(SECSuccess, PK11_Logout(slot_.get()));
  doPasswordCallbackCount = 0;
  PK11_SetPasswordFunc(doPasswordCallback);
  EXPECT_EQ(SECSuccess, PK11_Authenticate(slot_.get(), PR_FALSE, nullptr));
  PK11_SetPasswordFunc(nullptr);
  EXPECT_GE(doPasswordCallbackCount, 1);
  EXPECT_TRUE(PK11_IsLoggedIn(slot_.get(), nullptr));
}

INSTANTIATE_TEST_SUITE_P(
    ThreadSafetyVariants, Pkcs11AuthTest, ::testing::Values(false, true),
    [](const ::testing::TestParamInfo<bool>& param_info) {
      return param_info.param ? "NonThreadSafe" : "ThreadSafe";
    });

}  // namespace nss_test
