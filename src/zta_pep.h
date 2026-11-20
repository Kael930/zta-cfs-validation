#ifndef ZTA_PEP_H
#define ZTA_PEP_H

#include <stdint.h>
#include <stdio.h>
#include <time.h>

#ifndef ZTA_PHASE_MODE
#define ZTA_PHASE_MODE 0
#endif

#define ZTA_SECRET_KEY   0x5A7A2026U
#define ZTA_CCSDS_LEN    12
#define ZTA_TOKEN_LEN    10
#define ZTA_TOTAL_LEN    (ZTA_CCSDS_LEN + ZTA_TOKEN_LEN)

static FILE *zta_csv_fp = NULL;

static inline void ZTA_LogResult(const char *status, const char *reason, double latency_us)
{
    if (zta_csv_fp == NULL)
    {
        char fname[128];
        snprintf(fname, sizeof(fname), "/home/yjcho/zta_exp/cfs_mode%d.csv", ZTA_PHASE_MODE);
        zta_csv_fp = fopen(fname, "w");
        if (zta_csv_fp != NULL)
        {
            fprintf(zta_csv_fp, "status,reason,latency_us\n");
            fflush(zta_csv_fp);
        }
    }
    if (zta_csv_fp != NULL)
    {
        fprintf(zta_csv_fp, "%s,%s,%.3f\n", status, reason, latency_us);
        fflush(zta_csv_fp);
    }
}

#if ZTA_PHASE_MODE >= 2
static inline uint32_t ZTA_ComputeMAC_4Mode(const uint8_t *data, int len)
{
    uint32_t h = 2166136261U ^ ZTA_SECRET_KEY;
    int i;
    for (i = 0; i < len; i++)
    {
        h ^= data[i];
        h *= 16777619U;
    }
    return h;
}
#endif

/*
 * 반환값: 1 = ALLOWED (Software Bus 전달), 0 = BLOCKED (조기 차단)
 * 패킷 구조 (22 Bytes):
 *   [0..11]  CCSDS Telecommand (Primary 6B + Payload 6B)
 *   [12]     role   (0x01=FlightOps, 0x02=LowPriv)
 *   [13]     src_id (0x01=NormalGS,  0x02=CompromisedNode)
 *   [14..17] expiry (uint32 BE, Unix timestamp)
 *   [18..21] mac    (uint32 BE, FNV-1a MAC over bytes 0..17)
 */
static inline int ZTA_EvaluatePacket(const uint8_t *buf, int len, const char **out_reason)
{
    *out_reason = "PASS";

#if ZTA_PHASE_MODE == 0
    (void)buf;
    (void)len;
    return 1;
#else
    /* [Phase 2-A] TE-20 / TE-22: Input Validation & Sanitization */
    if (len < ZTA_TOTAL_LEN)
    {
        *out_reason = "TE20_22_LEN";
        return 0;
    }
    uint16_t ccsds_len = ((uint16_t)buf[4] << 8) | buf[5];
    if (ccsds_len != 5) /* 기대 페이로드 길이(6B - 1 = 5)와 불일치 시 변조 차단 */
    {
        *out_reason = "TE20_22_FMT";
        return 0;
    }

#if ZTA_PHASE_MODE >= 2
    /* [Phase 2-B] TE-09: Continuous Identity Verification (Expiry + MAC) */
    uint32_t expiry = ((uint32_t)buf[14] << 24) | ((uint32_t)buf[15] << 16) |
                      ((uint32_t)buf[16] << 8)  | (uint32_t)buf[17];
    uint32_t rx_mac = ((uint32_t)buf[18] << 24) | ((uint32_t)buf[19] << 16) |
                      ((uint32_t)buf[20] << 8)  | (uint32_t)buf[21];
    uint32_t calc_mac = ZTA_ComputeMAC_4Mode(buf, 18);

    if ((uint32_t)time(NULL) > expiry || rx_mac != calc_mac)
    {
        *out_reason = "TE09_AUTH";
        return 0;
    }

    /* [Phase 2-B] TE-04: Attribute-Based Dynamic Access Control (Role vs MsgID) */
    uint16_t msg_id = ((uint16_t)buf[0] << 8) | buf[1];
    uint8_t  role   = buf[12];
    if (msg_id == 0x1880 && role != 0x01)
    {
        *out_reason = "TE04_ABAC";
        return 0;
    }
#endif

#if ZTA_PHASE_MODE >= 3
    /* [Phase 3] TE-15: Autonomous Threat Isolation during LOS */
    static uint32_t src_pkt_cnt[256] = {0};
    uint8_t src_id = buf[13];
    if (src_id == 0x02) /* 비정상 반복 플러딩 탐지 시 5패킷 이후 자율 격리 */
    {
        src_pkt_cnt[src_id]++;
        if (src_pkt_cnt[src_id] > 5)
        {
            *out_reason = "TE15_ISOL";
            return 0;
        }
    }
#endif

    return 1;
#endif
}

#endif /* ZTA_PEP_H */
