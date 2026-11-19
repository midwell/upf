/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2026 Forsway Scandinavia AB
 */
#include "packet.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <memory>

#include "dpdk.h"
#include "packet_pool.h"

namespace {

class PacketCopyTest : public ::testing::Test {
 protected:
  // InitDpdk() is idempotent and aborts the process if EAL cannot be brought
  // up, so there is nothing here worth asserting afterwards.
  void SetUp() override {
    bess::InitDpdk();
    pool_ = std::make_unique<bess::PlainPacketPool>(64);
  }

  std::unique_ptr<bess::PlainPacketPool> pool_;
};

// A packet filling a buffer's data area and then grown into its headroom is
// longer than a fresh buffer's tailroom. That is the shape of a downlink packet
// at the Lawful Interception tee: GTP-U encapsulation and the 9-byte LI tag are
// prepended after it was received. Its copy was appended past the tailroom,
// which fails, and the null was copied to.
TEST_F(PacketCopyTest, CopiesAPacketThatGrewIntoItsHeadroom) {
  for (int growth : {0, 9, 53, SNBUF_HEADROOM}) {
    SCOPED_TRACE(growth);

    bess::Packet *src = pool_->Alloc();
    ASSERT_NE(src, nullptr);
    ASSERT_NE(src->append(src->tailroom()), nullptr);
    if (growth > 0) {
      ASSERT_NE(src->prepend(growth), nullptr);
    }

    const int len = src->total_len();
    ASSERT_EQ(len, SNBUF_DATA + growth);
    uint8_t *data = src->head_data<uint8_t *>();
    for (int i = 0; i < len; i++) {
      data[i] = static_cast<uint8_t>(i * 7 + 3);
    }

    bess::Packet *dst = bess::Packet::copy(src);
    ASSERT_NE(dst, nullptr);
    EXPECT_EQ(dst->total_len(), len);
    EXPECT_EQ(dst->data_len(), len);
    EXPECT_EQ(0, memcmp(dst->head_data(), src->head_data(), len));

    bess::Packet::Free(dst);
    bess::Packet::Free(src);
  }
}

// Only the first segment's data is copied, so a packet in several segments is
// refused, as an empty pool is, before any buffer is taken from the pool.
TEST_F(PacketCopyTest, RefusesAPacketInSeveralSegments) {
  bess::Packet *head = pool_->Alloc(100);
  bess::Packet *tail = pool_->Alloc(100);
  ASSERT_NE(head, nullptr);
  ASSERT_NE(tail, nullptr);
  ASSERT_EQ(0, rte_pktmbuf_chain(reinterpret_cast<rte_mbuf *>(head),
                                 reinterpret_cast<rte_mbuf *>(tail)));
  ASSERT_FALSE(head->is_linear());

  const size_t free_before = pool_->Size();
  EXPECT_EQ(bess::Packet::copy(head), nullptr);
  EXPECT_EQ(pool_->Size(), free_before);

  bess::Packet::Free(head);  // and its tail
}

}  // namespace
