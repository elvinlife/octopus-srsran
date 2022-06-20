/**
 * Copyright 2013-2021 Software Radio Systems Limited
 *
 * This file is part of srsRAN.
 *
 * srsRAN is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * srsRAN is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * A copy of the GNU Affero General Public License can be found in
 * the LICENSE file in the top-level directory of this distribution
 * and at http://www.gnu.org/licenses/.
 *
 */

#include "srsran/upper/rlc_um_base.h"
#include "srsran/interfaces/ue_rrc_interfaces.h"
#include <sstream>
#include <chrono>
using std::chrono::microseconds;
using std::chrono::milliseconds;
using std::chrono::duration_cast;
using std::chrono::system_clock;

namespace srsran {

rlc_um_base::rlc_um_base(srslog::basic_logger&      logger,
                         uint32_t                   lcid_,
                         srsue::pdcp_interface_rlc* pdcp_,
                         srsue::rrc_interface_rlc*  rrc_,
                         srsran::timer_handler*     timers_) :
  logger(logger), lcid(lcid_), pdcp(pdcp_), rrc(rrc_), timers(timers_), pool(byte_buffer_pool::get_instance())
{}

rlc_um_base::~rlc_um_base() {}

void rlc_um_base::stop()
{
  if (tx) {
    tx->stop();
  }

  if (rx) {
    rx->stop();
  }
}

rlc_mode_t rlc_um_base::get_mode()
{
  return rlc_mode_t::um;
}

uint32_t rlc_um_base::get_bearer()
{
  return lcid;
}

bool rlc_um_base::is_mrb()
{
  return cfg.um.is_mrb;
}

void rlc_um_base::reestablish()
{
  tx_enabled = false;

  if (tx) {
    tx->reestablish(); // calls stop and enables tx again
  }

  if (rx) {
    rx->reestablish(); // nothing else needed
  }

  tx_enabled = true;
}

void rlc_um_base::empty_queue()
{
  // Drop all messages in TX SDU queue
  if (tx) {
    tx->empty_queue();
  }
}

/****************************************************************************
 * PDCP interface
 ***************************************************************************/
void rlc_um_base::write_sdu(unique_byte_buffer_t sdu)
{
  if (not tx_enabled || not tx) {
    logger.debug("%s is currently deactivated. Dropping SDU (%d B)", rb_name.c_str(), sdu->N_bytes);
    metrics.num_lost_sdus++;
    return;
  }

  int sdu_bytes = sdu->N_bytes; //< Store SDU length for book-keeping
  if (tx->try_write_sdu(std::move(sdu)) == SRSRAN_SUCCESS) {
    metrics.num_tx_sdus++;
    metrics.num_tx_sdu_bytes += sdu_bytes;
  } else {
    metrics.num_lost_sdus++;
  }
}

void rlc_um_base::discard_sdu(uint32_t discard_sn)
{
  if (not tx_enabled || not tx) {
    logger.debug("%s is currently deactivated. Ignoring SDU discard (SN=%u)", rb_name.c_str(), discard_sn);
    return;
  }
  tx->discard_sdu(discard_sn);
  metrics.num_lost_sdus++;
}

bool rlc_um_base::sdu_queue_is_full()
{
  return tx->sdu_queue_is_full();
}

/****************************************************************************
 * MAC interface
 ***************************************************************************/

bool rlc_um_base::has_data()
{
  if (tx) {
    return tx->has_data();
  }
  return false;
}

uint32_t rlc_um_base::get_buffer_state()
{
  if (tx) {
    return tx->get_buffer_state();
  }
  return 0;
}

int rlc_um_base::read_pdu(uint8_t* payload, uint32_t nof_bytes)
{
  if (tx && tx_enabled) {
    uint32_t len = tx->build_data_pdu(payload, nof_bytes);
    if (len > 0) {
      metrics.num_tx_pdu_bytes += len;
      metrics.num_tx_pdus++;
    }
    return len;
  }
  return 0;
}

void rlc_um_base::write_pdu(uint8_t* payload, uint32_t nof_bytes)
{
  if (rx && rx_enabled) {
    metrics.num_rx_pdus++;
    metrics.num_rx_pdu_bytes += nof_bytes;
    rx->handle_data_pdu(payload, nof_bytes);
  }
}

rlc_bearer_metrics_t rlc_um_base::get_metrics()
{
  return metrics;
}

void rlc_um_base::reset_metrics()
{
  metrics = {};
}

/****************************************************************************
 * Helper functions
 ***************************************************************************/

std::string rlc_um_base::get_rb_name(srsue::rrc_interface_rlc* rrc, uint32_t lcid, bool is_mrb)
{
  if (is_mrb) {
    std::stringstream ss;
    ss << "MRB" << lcid;
    return ss.str();
  } else {
    return rrc->get_rb_name(lcid);
  }
}

rlc_um_base::app_header_t::app_header_t(unique_byte_buffer_t& tx_sdu)
{
  memcpy(&ip_field_, tx_sdu->msg + 10, sizeof(ip_field_));
  ip_field_ = ntohl(ip_field_);
  memcpy(&udp_field_, tx_sdu->msg + 22, sizeof(udp_field_));
  udp_field_ = ntohl(udp_field_);
  uint8_t* app_header = tx_sdu->msg + app_header_offset;
  memcpy(&seq_, app_header, sizeof(seq_));
  seq_ = ntohl(seq_);
  memcpy(&msg_field_, app_header + 4, sizeof(msg_field_));
  msg_field_ = ntohl(msg_field_);
  memcpy(&wildcard_, app_header + 8, sizeof(wildcard_));
  wildcard_ = ntohl(wildcard_);
}

inline uint32_t rlc_um_base::app_header_t::seq() const
{
  return seq_;
}
inline int32_t rlc_um_base::app_header_t::msg_no() const
{
  return msg_field_ & 0x1fffffff;
}
rlc_um_base::pkt_pos_t rlc_um_base::app_header_t::pkt_pos() const
{
  if ((msg_field_ & 0xc0000000) == 0x80000000) {
    return FIRST;
  }
  else if ((msg_field_ & 0xc0000000) == 0x40000000) {
    return LAST;
  }
  else if ((msg_field_ & 0xc0000000) == 0x00000000) {
    return MID;
  }
  else {
    return SOLO;
  }
}
inline uint32_t rlc_um_base::app_header_t::priority() const
{
  return (wildcard_ & 0xe0000000) >> 29;
}
inline uint32_t rlc_um_base::app_header_t::priority_threshold() const
{ 
  return (wildcard_ & 0x1c000000) >> 26;
}
inline bool rlc_um_base::app_header_t::is_preempt() const
{ 
  return (wildcard_ & 0x2000000);
}
inline uint32_t rlc_um_base::app_header_t::slack_time() const
{ 
  return (wildcard_ & 0x01ff0000) >> 16;
}
inline uint32_t rlc_um_base::app_header_t::bitrate() const
{
  return wildcard_ & 0x0000ffff;
}
inline bool rlc_um_base::app_header_t::is_udp() const
{ 
  return ((ip_field_ >> 16) & 0x000000ff) == 17;
}
// the first bit of seq is 0 for octopus data packets, and it's 1 for control packets
// very handwavy design(first two bits are 0, so it's octopus data packets)
inline bool rlc_um_base::app_header_t::is_octopus() const
{ 
  return is_udp() && !( seq_ & 0xa0000000 );
}
inline uint16_t rlc_um_base::app_header_t::dst_port() const
{ 
  return udp_field_ & 0x0000ffff;
}

/****************************************************************************
 * Rx subclass implementation (base)
 ***************************************************************************/

rlc_um_base::rlc_um_base_rx::rlc_um_base_rx(rlc_um_base* parent_) :
  pool(parent_->pool),
  logger(parent_->logger),
  timers(parent_->timers),
  pdcp(parent_->pdcp),
  rrc(parent_->rrc),
  cfg(parent_->cfg),
  metrics(parent_->metrics),
  lcid(parent_->lcid)
{}

rlc_um_base::rlc_um_base_rx::~rlc_um_base_rx() {}

/****************************************************************************
 * Tx subclass implementation (base)
 ***************************************************************************/

rlc_um_base::rlc_um_base_tx::rlc_um_base_tx(rlc_um_base* parent_) :
  logger(parent_->logger), pool(parent_->pool), parent(parent_)
{}

rlc_um_base::rlc_um_base_tx::~rlc_um_base_tx() {}

void rlc_um_base::rlc_um_base_tx::stop()
{
  empty_queue();
  reset();
}

void rlc_um_base::rlc_um_base_tx::reestablish()
{
  stop();
  // bearer is enabled in base class
}

void rlc_um_base::rlc_um_base_tx::empty_queue()
{
  std::lock_guard<std::mutex> lock(mutex);

  // deallocate all SDUs in transmit queue
  while (not tx_sdu_queue.is_empty()) {
    unique_byte_buffer_t buf = tx_sdu_queue.read();
  }

  // deallocate SDU that is currently processed
  tx_sdu.reset();
}

bool rlc_um_base::rlc_um_base_tx::has_data()
{
  return (tx_sdu != nullptr || !tx_sdu_queue.is_empty());
}

void rlc_um_base::rlc_um_base_tx::write_sdu(unique_byte_buffer_t sdu)
{
  if (sdu) {
    logger.warning(sdu->msg,
                sdu->N_bytes,
                "%s Tx(write_sdu) SDU (%d B, tx_sdu_queue_len=%d)",
                rb_name.c_str(),
                sdu->N_bytes,
                tx_sdu_queue.size());
    tx_sdu_queue.write(std::move(sdu));
  } else {
    logger.warning("NULL SDU pointer in write_sdu()");
  }
}

int rlc_um_base::rlc_um_base_tx::try_write_sdu(unique_byte_buffer_t sdu)
{
  if (sdu) {
    uint8_t*                                 msg_ptr   = sdu->msg;
    uint32_t                                 nof_bytes = sdu->N_bytes;

    app_header_t app_header(sdu);
    if (app_header.is_octopus()) {
      uint16_t dstport = app_header.dst_port();
      if( app_header.pkt_pos() == FIRST || app_header.pkt_pos() == LAST ) {
        if( frame_counter_[dstport].find( app_header.msg_no() )
            == frame_counter_[dstport].end() ) 
          frame_counter_[dstport][ app_header.msg_no() ] = 1;
        else
          frame_counter_[dstport][ app_header.msg_no() ] += 1;
      }
      else if ( app_header.pkt_pos() == SOLO ) {
        assert( frame_counter_[dstport].find( app_header.msg_no() ) == frame_counter_[dstport].end() );
        frame_counter_[dstport][ app_header.msg_no() ] = 2;
      }
      if (app_header.pkt_pos() == LAST || app_header.pkt_pos() == SOLO) {
        if (app_header.is_preempt()) {
          int32_t dropper_msgno = app_header.msg_no();
          uint32_t prio_threshold = app_header.priority_threshold();
          if (prio_to_droppers_.find(dstport) == prio_to_droppers_.end()) {
            for (int i = 0; i < max_prio; ++i)
              prio_to_droppers_[dstport][i] = -1;
          }
          if (dropper_msgno > prio_to_droppers_[dstport][prio_threshold]) {
            prio_to_droppers_[dstport][prio_threshold] = dropper_msgno;
          }
        }
      }
    }

    srsran::error_type<unique_byte_buffer_t> ret       = tx_sdu_queue.try_write(std::move(sdu));
    if (ret) {
      if (app_header.is_octopus()) {
        logger.warning(
            msg_ptr, nof_bytes, "%s Tx(try_write_sdu) SDU (size: %dB seq: %d msg_no: %d pkt_pos: %d queue_len: %d)",
            rb_name.c_str(), nof_bytes,
            app_header.seq(), app_header.msg_no(),
            app_header.pkt_pos(), tx_sdu_queue.size());
      }
      else {
        logger.warning(
            msg_ptr, nof_bytes, "%s Tx SDU (size: %dB seq: 0 msg_no: 0 tx_sdu_queue_len: %d)",
            rb_name.c_str(), nof_bytes,
            tx_sdu_queue.size());
      }
      return SRSRAN_SUCCESS;
    } else {
      logger.warning(ret.error()->msg,
                     ret.error()->N_bytes,
                     "[Dropped SDU] %s Tx SDU (%d B, tx_sdu_queue_len=%d)",
                     rb_name.c_str(),
                     ret.error()->N_bytes,
                     tx_sdu_queue.size());
    }
  } else {
    logger.warning("NULL SDU pointer in write_sdu()");
  }
  return SRSRAN_ERROR;
}

void rlc_um_base::rlc_um_base_tx::discard_sdu(uint32_t discard_sn)
{
  logger.warning("RLC UM: Discard SDU not implemented yet.");
}

bool rlc_um_base::rlc_um_base_tx::sdu_queue_is_full()
{
  return tx_sdu_queue.is_full();
}

int rlc_um_base::rlc_um_base_tx::build_data_pdu(uint8_t* payload, uint32_t nof_bytes)
{
  unique_byte_buffer_t pdu;
  {
    std::lock_guard<std::mutex> lock(mutex);
    logger.debug("MAC opportunity - %d bytes", nof_bytes);

    if (tx_sdu == nullptr && tx_sdu_queue.is_empty()) {
      logger.info("No data available to be sent");
      return 0;
    }

    pdu = make_byte_buffer();
    if (!pdu || pdu->N_bytes != 0) {
      logger.error("Failed to allocate PDU buffer");
      return 0;
    }
  }

  // dequeue rate estimation
  size_t min_samples = 4;
  int sample_interval = 50; // 50 milliseconds
  uint64_t ts_delivery = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
  uint64_t ts_front = dequeue_trace_.front().first;
  dequeue_rate_ = 0xffffffff;
  if (dequeue_trace_.size() >= min_samples && (ts_front < ts_delivery)) {
    int total_bytes = dequeue_bytes_ + nof_bytes - dequeue_trace_.front().second;
    dequeue_rate_ = total_bytes * 8.0 / (ts_delivery - ts_front);
  }
  dequeue_bytes_ += nof_bytes;
  dequeue_trace_.push_back(
    std::pair<uint64_t, uint32_t>(ts_delivery, nof_bytes));
  while (dequeue_trace_.size() > min_samples &&
    dequeue_trace_.front().first < (ts_delivery - sample_interval)) {
      dequeue_bytes_ -= dequeue_trace_.front().second;
      dequeue_trace_.pop_front();
  }

  return build_data_pdu(std::move(pdu), payload, nof_bytes);
}

std::pair<bool, unique_byte_buffer_t>
rlc_um_base::rlc_um_base_tx::dequeue_front()
{
  unique_byte_buffer_t pkt_sdu = tx_sdu_queue.read();
  app_header_t app_header(pkt_sdu);
  logger.info("dequeue_front size: %u seq: %u msg_no: %d pkt_pos: %d queue_len: %u",
      pkt_sdu->N_bytes, app_header.seq(), 
      app_header.msg_no(), app_header.pkt_pos(),
      tx_sdu_queue.size());
  if (!app_header.is_octopus()) {
    return std::pair<bool, unique_byte_buffer_t>(false, std::move(pkt_sdu));
  }
  uint16_t dstport = app_header.dst_port();
  bool pkt_is_drop = false;
  uint64_t ts_microsecond = duration_cast<microseconds>(system_clock::now().time_since_epoch()).count();
  if ( (frame_counter_[dstport].find(app_header.msg_no())
    != frame_counter_[dstport].end() ) && 
    frame_counter_[dstport][app_header.msg_no()] == 2) {
      // sojourn time tbw..
      int32_t latest_dropper = -1;
      unsigned int sojourn_time = 0;
      for (unsigned int i = 0; i <= app_header.priority(); ++i) {
        if (prio_to_droppers_[dstport][i] > latest_dropper) {
          latest_dropper = prio_to_droppers_[dstport][i];
        }
      }
      if (app_header.bitrate() > dequeue_rate_ && 
      sojourn_time >= app_header.slack_time() ) {
        //pkt_is_drop = true;
        msg_in_drop_[dstport] = app_header.msg_no();
        logger.warning("drop-prim-2, ts: %lu seq: %u msg_no: %d"
        " bitrate: %u dequeue_rate: %u slack_time: %u frame_counter: %u\n",
          ts_microsecond, app_header.seq(), app_header.msg_no(), 
          app_header.bitrate(), dequeue_rate_, app_header.slack_time(),
          frame_counter_[dstport].size()
          );
      }
      else if (app_header.msg_no() < latest_dropper &&
      sojourn_time >= app_header.slack_time()) {
        //pkt_is_drop = true;
        msg_in_drop_[dstport] = app_header.msg_no();
        logger.warning("drop-prim-1, ts: %lu seq: %u msg_no: %d"
          " priority: %u dropper: %d slack_time: %u frame_counter: %u\n",
          ts_microsecond, app_header.seq(), app_header.msg_no(),
          app_header.priority(), latest_dropper, app_header.slack_time(),
          frame_counter_[dstport].size()
          );
      }
  }
  if (app_header.msg_no() == msg_in_drop_[dstport]) {
    logger.warning("drop-pkt, ts: %lu seq: %u msg_no: %d",
        ts_microsecond, app_header.seq(), app_header.msg_no());
    pkt_is_drop = true;
  }

  // delete the msg from record
  if (app_header.pkt_pos() == FIRST || app_header.pkt_pos() == LAST) {
    if (frame_counter_[dstport].find(app_header.msg_no()) == frame_counter_[dstport].end()) {
      logger.error("Dequeue a non-existing packet seq: %u msg_no: %d",
        app_header.seq(), app_header.msg_no());
      frame_counter_[dstport][app_header.msg_no()] = 0;
    }
    else {
      frame_counter_[dstport].at( app_header.msg_no() ) -= 1;
    }
    if (frame_counter_[dstport][app_header.msg_no()] == 0) {
      frame_counter_[dstport].erase( app_header.msg_no() );
    }
  }
  else if (app_header.pkt_pos() == SOLO) {
    assert (frame_counter_[dstport][app_header.msg_no()] == 2);
    frame_counter_[dstport].erase( app_header.msg_no() );
  }
  return std::pair<bool, unique_byte_buffer_t>(pkt_is_drop, std::move(pkt_sdu));
}

} // namespace srsran
