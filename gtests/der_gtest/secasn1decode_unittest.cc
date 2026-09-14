/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "gtest/gtest.h"
#include "scoped_ptrs_util.h"

#include <climits>
#include <cstdint>
#include <vector>

#include "nss.h"
#include "prerror.h"
#include "secasn1.h"
#include "secasn1t.h"
#include "secerr.h"
#include "secport.h"

class SECASN1DecodeTest : public ::testing::Test {};

struct Item {
  SECItem value;
};

const SEC_ASN1Template ItemTemplate[] = {
    {SEC_ASN1_SEQUENCE, 0, NULL, sizeof(struct Item)}, {0}};

static const SEC_ASN1Template ItemsTemplate[] = {
    {SEC_ASN1_SEQUENCE_OF, 0, ItemTemplate}, {0}};

struct Container {
  struct Item** items;
};

const SEC_ASN1Template ContainerTemplate[] = {
    {SEC_ASN1_SEQUENCE, 0, NULL, sizeof(struct Container)},
    {SEC_ASN1_CONSTRUCTED | SEC_ASN1_CONTEXT_SPECIFIC | SEC_ASN1_EXPLICIT | 0,
     offsetof(struct Container, items), ItemsTemplate},
    {0}};

// clang-format off
const unsigned char kEndOfContentsInDefiniteLengthContext[] = {
    0x30, 0x06,
      0xa0, 0x04,
        0x30, 0x00,
        0x00, 0x00, // EOC in definite length context
};
// clang-format on

TEST_F(SECASN1DecodeTest, EndOfContentsInDefiniteLengthContext) {
  ScopedPLArenaPool pool(PORT_NewArena(1024));
  struct Container* decoded = reinterpret_cast<struct Container*>(
      PORT_ArenaZAlloc(pool.get(), sizeof(struct Container)));
  SEC_ASN1DecoderContext* ctx =
      SEC_ASN1DecoderStart(pool.get(), decoded, ContainerTemplate);
  ASSERT_TRUE(ctx);
  ASSERT_EQ(
      SEC_ASN1DecoderUpdate(
          ctx,
          reinterpret_cast<const char*>(kEndOfContentsInDefiniteLengthContext),
          sizeof(kEndOfContentsInDefiniteLengthContext)),
      SECFailure);
  ASSERT_EQ(PR_GetError(), SEC_ERROR_BAD_DER);
  ASSERT_EQ(SECSuccess, SEC_ASN1DecoderFinish(ctx));
}

// clang-format off
const unsigned char kContentsTooShort[] = {
    0x30, 0x06,
      0xa0, 0x04,
        0x30, 0x00, // There should be two more bytes after this
};
// clang-format on

TEST_F(SECASN1DecodeTest, ContentsTooShort) {
  ScopedPLArenaPool pool(PORT_NewArena(1024));
  struct Container* decoded = reinterpret_cast<struct Container*>(
      PORT_ArenaZAlloc(pool.get(), sizeof(struct Container)));
  SEC_ASN1DecoderContext* ctx =
      SEC_ASN1DecoderStart(pool.get(), decoded, ContainerTemplate);
  ASSERT_TRUE(ctx);
  ASSERT_EQ(SEC_ASN1DecoderUpdate(
                ctx, reinterpret_cast<const char*>(kContentsTooShort),
                sizeof(kContentsTooShort)),
            SECFailure);
  ASSERT_EQ(PR_GetError(), SEC_ERROR_BAD_DER);
  ASSERT_EQ(SECSuccess, SEC_ASN1DecoderFinish(ctx));
}

static const SEC_ASN1Template kOctetStringTemplate[] = {{SEC_ASN1_OCTET_STRING},
                                                        {0}};

// A valid 11-byte OCTET STRING (tag + 1-byte length + 9 bytes content).
// clang-format off
const unsigned char kElevenByteOctetString[] = {
    0x04, 0x09,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
};
// clang-format on

// An OCTET STRING header claiming a length that exceeds
// SEC_ASN1D_MAX_INPUT_SIZE.
// clang-format off
const unsigned char kOversizedOctetStringHeader[] = {
    0x04, 0x84,              // OCTET STRING, 4-byte length field
    0x10, 0x00, 0x00, 0x01, // 0x10000001 = 268435457 > 256MB
};
// clang-format on

TEST_F(SECASN1DecodeTest, DefaultLimitRejectsOversizedElement) {
  ScopedPLArenaPool pool(PORT_NewArena(1024));
  SECItem dest = {siBuffer, nullptr, 0};
  SEC_ASN1DecoderContext* ctx =
      SEC_ASN1DecoderStart(pool.get(), &dest, kOctetStringTemplate);
  ASSERT_TRUE(ctx);
  SECStatus rv = SEC_ASN1DecoderUpdate(
      ctx, reinterpret_cast<const char*>(kOversizedOctetStringHeader),
      sizeof(kOversizedOctetStringHeader));
  ASSERT_EQ(rv, SECFailure);
  ASSERT_EQ(PR_GetError(), SEC_ERROR_BAD_DER);
  ASSERT_EQ(SECSuccess, SEC_ASN1DecoderFinish(ctx));
}

TEST_F(SECASN1DecodeTest, CustomLimitRejectsOversizedElement) {
  ScopedPLArenaPool pool(PORT_NewArena(1024));
  SECItem dest = {siBuffer, nullptr, 0};
  SEC_ASN1DecoderContext* ctx =
      SEC_ASN1DecoderStart(pool.get(), &dest, kOctetStringTemplate);
  ASSERT_TRUE(ctx);
  // Lower the limit to 8 bytes — the 11-byte string should be rejected.
  SEC_ASN1DecoderSetMaximumElementSize(ctx, 8);
  SECStatus rv = SEC_ASN1DecoderUpdate(
      ctx, reinterpret_cast<const char*>(kElevenByteOctetString),
      sizeof(kElevenByteOctetString));
  ASSERT_EQ(rv, SECFailure);
  ASSERT_EQ(PR_GetError(), SEC_ERROR_BAD_DER);
  ASSERT_EQ(SECSuccess, SEC_ASN1DecoderFinish(ctx));
}

TEST_F(SECASN1DecodeTest, ZeroLimitOptOut) {
  ScopedPLArenaPool pool(PORT_NewArena(1024));
  SECItem dest = {siBuffer, nullptr, 0};
  SEC_ASN1DecoderContext* ctx =
      SEC_ASN1DecoderStart(pool.get(), &dest, kOctetStringTemplate);
  ASSERT_TRUE(ctx);
  // Setting limit to 0 disables the check; the 11-byte string should succeed.
  SEC_ASN1DecoderSetMaximumElementSize(ctx, 0);
  SECStatus rv = SEC_ASN1DecoderUpdate(
      ctx, reinterpret_cast<const char*>(kElevenByteOctetString),
      sizeof(kElevenByteOctetString));
  ASSERT_EQ(rv, SECSuccess);
  ASSERT_EQ(SECSuccess, SEC_ASN1DecoderFinish(ctx));
}

TEST_F(SECASN1DecodeTest, OneShotDecodeLimitExceeded) {
  // SEC_ASN1Decode rejects input larger than SEC_ASN1D_MAX_INPUT_SIZE.
  SECItem dest = {siBuffer, nullptr, 0};
  long oversize = static_cast<long>(SEC_ASN1D_MAX_INPUT_SIZE) + 1;
  const char dummy = 0;
  SECStatus rv =
      SEC_ASN1Decode(nullptr, &dest, kOctetStringTemplate, &dummy, oversize);
  ASSERT_EQ(rv, SECFailure);
  ASSERT_EQ(PR_GetError(), SEC_ERROR_BAD_DER);
}

TEST_F(SECASN1DecodeTest, ElementSizeLimitEnforcedAcrossChunks) {
  ScopedPLArenaPool pool(PORT_NewArena(1024));
  SECItem dest = {siBuffer, nullptr, 0};
  SEC_ASN1DecoderContext* ctx =
      SEC_ASN1DecoderStart(pool.get(), &dest, kOctetStringTemplate);
  ASSERT_TRUE(ctx);
  // Deliver the oversized header one byte at a time to verify the limit is
  // enforced even when input arrives in small chunks.
  SECStatus rv = SECSuccess;
  for (size_t i = 0; i < sizeof(kOversizedOctetStringHeader); i++) {
    rv = SEC_ASN1DecoderUpdate(
        ctx, reinterpret_cast<const char*>(kOversizedOctetStringHeader) + i, 1);
    if (rv != SECSuccess) break;
  }
  ASSERT_EQ(rv, SECFailure);
  ASSERT_EQ(PR_GetError(), SEC_ERROR_BAD_DER);
  ASSERT_EQ(SECSuccess, SEC_ASN1DecoderFinish(ctx));
}
