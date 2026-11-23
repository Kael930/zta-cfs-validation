#ifndef ZTA_PEP_H
#define ZTA_PEP_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef ZTA_PHASE_MODE
#define ZTA_PHASE_MODE 0
#endif

/*
 * Packet Layout (64 Bytes):
 *   [0..11]  CCSDS Telecommand (Primary 6B + Payload 6B)
 *   [12]     role      (0x01=FlightOps, 0x02=LowPriv)
 *   [13]     src_id    (0x01..0xFF, sender identifier)
 *   [14]     pkt_class (logging tag only; NEVER used in security decision)
 *                      0=WARMUP, 1=BENIGN, 2=ATK1_MALFORM, 3=ATK2_REPLAY,
 *                      4=ATK3_ABAC, 5=ATK4_LOS_FLOOD
 *   [15]     los_state (0=AOS, 1=LOS)
 *   [16..23] seq_num   (uint64 BE, monotonic anti-replay counter per src_id)
 *   [24..27] expiry    (uint32 BE, Unix timestamp)
 *   [28..31] run_id    (uint32 BE, experiment repetition index for logging)
 *   [32..63] hmac      (32B HMAC-SHA-256 over bytes 0..31)
 */
#define ZTA_CCSDS_LEN       12
#define ZTA_HEADER_AUTH_LEN 32
#define ZTA_HMAC_LEN        32
#define ZTA_TOTAL_LEN       (ZTA_HEADER_AUTH_LEN + ZTA_HMAC_LEN)

/* Generalized Mode 3 (TE-15) Time-Window Rate Limit under LOS */
#define ZTA_LOS_WINDOW_SEC  1.0
#define ZTA_LOS_MAX_PKTS    5

/* =========================================================================
 * Minimal Self-Contained SHA-256 & HMAC-SHA-256 (FIPS 180-4 / RFC 2104)
 * Zero external library dependency for clean cFS flight-software builds.
 * ========================================================================= */
#if ZTA_PHASE_MODE >= 2

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t  data[64];
    size_t   datalen;
} ZTA_SHA256_CTX;

static const uint32_t zta_sha256_k[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
};

static inline uint32_t zta_rotr32(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32U - n));
}

static inline void zta_sha256_transform(ZTA_SHA256_CTX *ctx, const uint8_t data[64]) {
    uint32_t m[64];
    uint32_t a, b, c, d, e, f, g, h, t1, t2;
    int i, j;

    for (i = 0, j = 0; i < 16; ++i, j += 4) {
        m[i] = ((uint32_t)data[j] << 24) | ((uint32_t)data[j + 1] << 16) |
               ((uint32_t)data[j + 2] << 8) | ((uint32_t)data[j + 3]);
    }
    for (; i < 64; ++i) {
        uint32_t s0 = zta_rotr32(m[i - 15], 7) ^ zta_rotr32(m[i - 15], 18) ^ (m[i - 15] >> 3);
        uint32_t s1 = zta_rotr32(m[i - 2], 17) ^ zta_rotr32(m[i - 2], 19) ^ (m[i - 2] >> 10);
        m[i] = m[i - 16] + s0 + m[i - 7] + s1;
    }

    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];

    for (i = 0; i < 64; ++i) {
        uint32_t S1 = zta_rotr32(e, 6) ^ zta_rotr32(e, 11) ^ zta_rotr32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        t1 = h + S1 + ch + zta_sha256_k[i] + m[i];
        uint32_t S0 = zta_rotr32(a, 2) ^ zta_rotr32(a, 13) ^ zta_rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        t2 = S0 + maj;

        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static inline void zta_sha256_init(ZTA_SHA256_CTX *ctx) {
    ctx->datalen = 0;
    ctx->bitlen  = 0;
    ctx->state[0] = 0x6a09e667U; ctx->state[1] = 0xbb67ae85U;
    ctx->state[2] = 0x3c6ef372U; ctx->state[3] = 0xa54ff53aU;
    ctx->state[4] = 0x510e527fU; ctx->state[5] = 0x9b05688cU;
    ctx->state[6] = 0x1f83d9abU; ctx->state[7] = 0x5be0cd19U;
}

static inline void zta_sha256_update(ZTA_SHA256_CTX *ctx, const uint8_t *data, size_t len) {
    size_t i;
    for (i = 0; i < len; ++i) {
        ctx->data[ctx->datalen++] = data[i];
        if (ctx->datalen == 64) {
            zta_sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

static inline void zta_sha256_final(ZTA_SHA256_CTX *ctx, uint8_t hash[32]) {
    size_t i = ctx->datalen;
    ctx->data[i++] = 0x80;
    if (i > 56) {
        while (i < 64) ctx->data[i++] = 0x00;
        zta_sha256_transform(ctx, ctx->data);
        i = 0;
    }
    while (i < 56) ctx->data[i++] = 0x00;

    ctx->bitlen += (uint64_t)ctx->datalen * 8ULL;
    for (i = 0; i < 8; ++i) {
        ctx->data[63 - i] = (uint8_t)((ctx->bitlen >> (i * 8)) & 0xFFU);
    }
    zta_sha256_transform(ctx, ctx->data);

    for (i = 0; i < 8; ++i) {
        hash[i * 4 + 0] = (uint8_t)((ctx->state[i] >> 24) & 0xFFU);
        hash[i * 4 + 1] = (uint8_t)((ctx->state[i] >> 16) & 0xFFU);
        hash[i * 4 + 2] = (uint8_t)((ctx->state[i] >> 8)  & 0xFFU);
        hash[i * 4 + 3] = (uint8_t)((ctx->state[i])       & 0xFFU);
    }
}

static inline void ZTA_HMAC_SHA256(const uint8_t *key, size_t key_len,
                                   const uint8_t *msg, size_t msg_len,
                                   uint8_t out_mac[32]) {
    uint8_t k_pad[64];
    uint8_t i_key_pad[64];
    uint8_t o_key_pad[64];
    uint8_t inner_hash[32];
    ZTA_SHA256_CTX ctx;
    size_t i;

    memset(k_pad, 0, sizeof(k_pad));
    if (key_len > 64) {
        zta_sha256_init(&ctx);
        zta_sha256_update(&ctx, key, key_len);
        zta_sha256_final(&ctx, k_pad);
    } else {
        memcpy(k_pad, key, key_len);
    }

    for (i = 0; i < 64; ++i) {
        i_key_pad[i] = k_pad[i] ^ 0x36U;
        o_key_pad[i] = k_pad[i] ^ 0x5cU;
    }

    zta_sha256_init(&ctx);
    zta_sha256_update(&ctx, i_key_pad, 64);
    zta_sha256_update(&ctx, msg, msg_len);
    zta_sha256_final(&ctx, inner_hash);

    zta_sha256_init(&ctx);
    zta_sha256_update(&ctx, o_key_pad, 64);
    zta_sha256_update(&ctx, inner_hash, 32);
    zta_sha256_final(&ctx, out_mac);
}

/* Constant-time MAC comparison to prevent timing side-channels */
static inline int ZTA_ConstTimeEqual(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0;
    size_t i;
    for (i = 0; i < len; ++i) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return (diff == 0);
}

static inline const uint8_t *ZTA_GetKey(size_t *out_len) {
    static int initialized = 0;
    static uint8_t key_buf[64];
    static size_t key_len = 0;
    if (!initialized) {
        const char *env_key = getenv("ZTA_HMAC_KEY");
        if (env_key != NULL && strlen(env_key) > 0) {
            key_len = strlen(env_key);
            if (key_len > sizeof(key_buf)) key_len = sizeof(key_buf);
            memcpy(key_buf, env_key, key_len);
        } else {
            /* Testbed fallback only if ZTA_HMAC_KEY is not exported */
            const char *fallback = "ZTA_TESTBED_DEFAULT_KEY_CHANGE_ME";
            key_len = strlen(fallback);
            memcpy(key_buf, fallback, key_len);
        }
        initialized = 1;
    }
    *out_len = key_len;
    return key_buf;
}

#endif /* ZTA_PHASE_MODE >= 2 */

/* =========================================================================
 * CSV Logging (Expanded Schema for Independent Verification)
 * ========================================================================= */
static FILE *zta_csv_fp = NULL;

static inline const char *ZTA_ClassName(uint8_t cls) {
    switch (cls) {
        case 0: return "WARMUP";
        case 1: return "BENIGN";
        case 2: return "ATK1_MALFORM";
        case 3: return "ATK2_REPLAY";
        case 4: return "ATK3_ABAC";
        case 5: return "ATK4_LOS_FLOOD";
        default: return "UNKNOWN";
    }
}

static inline void ZTA_LogResult(const uint8_t *buf, int len,
                                 const char *status, const char *reason,
                                 double latency_us)
{
    uint8_t  src_id    = (len >= 14) ? buf[13] : 0;
    uint8_t  pkt_class = (len >= 15) ? buf[14] : 255;
    uint8_t  los_state = (len >= 16) ? buf[15] : 0;
    uint64_t seq_num   = 0;
    uint32_t run_id    = 0;

    if (len >= 24) {
        seq_num = ((uint64_t)buf[16] << 56) | ((uint64_t)buf[17] << 48) |
                  ((uint64_t)buf[18] << 40) | ((uint64_t)buf[19] << 32) |
                  ((uint64_t)buf[20] << 24) | ((uint64_t)buf[21] << 16) |
                  ((uint64_t)buf[22] << 8)  | ((uint64_t)buf[23]);
    }
    if (len >= 32) {
        run_id = ((uint32_t)buf[28] << 24) | ((uint32_t)buf[29] << 16) |
                 ((uint32_t)buf[30] << 8)  | ((uint32_t)buf[31]);
    }

    if (zta_csv_fp == NULL) {
        const char *log_dir = getenv("ZTA_LOG_DIR");
        if (log_dir == NULL || strlen(log_dir) == 0) {
            log_dir = "/home/yjcho/zta_exp";
        }
        char fname[256];
        snprintf(fname, sizeof(fname), "%s/cfs_mode%d_v2.csv", log_dir, ZTA_PHASE_MODE);
        zta_csv_fp = fopen(fname, "w");
        if (zta_csv_fp != NULL) {
            fprintf(zta_csv_fp, "run_id,mode,pkt_class,src_id,seq_num,los_state,status,reason,latency_us\n");
            fflush(zta_csv_fp);
        }
    }
    if (zta_csv_fp != NULL) {
        fprintf(zta_csv_fp, "%u,%d,%s,%u,%llu,%u,%s,%s,%.3f\n",
                run_id, ZTA_PHASE_MODE, ZTA_ClassName(pkt_class),
                (unsigned)src_id, (unsigned long long)seq_num,
                (unsigned)los_state, status, reason, latency_us);
        fflush(zta_csv_fp);
    }
}

/* =========================================================================
 * Anti-Replay Sliding Window (64-bit bitmap per src_id)
 * ========================================================================= */
#if ZTA_PHASE_MODE >= 2
typedef struct {
    uint8_t  initialized;
    uint64_t max_seq;
    uint64_t window_mask;
} ZTA_ReplayState;

static ZTA_ReplayState zta_replay_tbl[256];

/* Returns 1 if fresh (accepted), 0 if replay/stale (blocked) */
static inline int ZTA_CheckAndUpdateReplay(uint8_t src_id, uint64_t seq) {
    ZTA_ReplayState *st = &zta_replay_tbl[src_id];
    if (!st->initialized) {
        st->initialized = 1;
        st->max_seq     = seq;
        st->window_mask = 1ULL;
        return 1;
    }
    if (seq > st->max_seq) {
        uint64_t shift = seq - st->max_seq;
        if (shift >= 64ULL) {
            st->window_mask = 1ULL;
        } else {
            st->window_mask = (st->window_mask << shift) | 1ULL;
        }
        st->max_seq = seq;
        return 1;
    }
    uint64_t diff = st->max_seq - seq;
    if (diff >= 64ULL) {
        return 0; /* Too old */
    }
    uint64_t bit = 1ULL << diff;
    if (st->window_mask & bit) {
        return 0; /* Duplicate replay */
    }
    st->window_mask |= bit;
    return 1;
}
#endif

/* =========================================================================
 * Generalized Autonomous LOS Rate-Limiter / Isolation (All src_ids)
 * ========================================================================= */
#if ZTA_PHASE_MODE >= 3
typedef struct {
    double   win_start_sec;
    uint32_t win_count;
    uint8_t  quarantined;
} ZTA_SrcRateState;

static ZTA_SrcRateState zta_rate_tbl[256];

static inline double ZTA_MonotonicSec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}
#endif

/*
 * Main Onboard PEP Evaluation Function
 * Returns: 1 = ALLOWED (forward to cFS Software Bus), 0 = BLOCKED (early drop)
 */
static inline int ZTA_EvaluatePacket(const uint8_t *buf, int len, const char **out_reason)
{
    *out_reason = "PASS";

#if ZTA_PHASE_MODE == 0
    (void)buf;
    (void)len;
    return 1;
#else
    /* [Mode 1] TE-20 / TE-22: Input Validation & Format Sanitization */
    if (len < ZTA_TOTAL_LEN) {
        *out_reason = "TE20_22_LEN";
        return 0;
    }
    uint16_t ccsds_len = ((uint16_t)buf[4] << 8) | buf[5];
    if (ccsds_len != 5) {
        *out_reason = "TE20_22_FMT";
        return 0;
    }

#if ZTA_PHASE_MODE >= 2
    /* [Mode 2] TE-09: HMAC-SHA-256 Authentication + Expiry + True Anti-Replay */
    uint8_t  src_id = buf[13];
    uint64_t seq    = ((uint64_t)buf[16] << 56) | ((uint64_t)buf[17] << 48) |
                      ((uint64_t)buf[18] << 40) | ((uint64_t)buf[19] << 32) |
                      ((uint64_t)buf[20] << 24) | ((uint64_t)buf[21] << 16) |
                      ((uint64_t)buf[22] << 8)  | ((uint64_t)buf[23]);
    uint32_t expiry = ((uint32_t)buf[24] << 24) | ((uint32_t)buf[25] << 16) |
                      ((uint32_t)buf[26] << 8)  | ((uint32_t)buf[27]);

    size_t key_len = 0;
    const uint8_t *key = ZTA_GetKey(&key_len);
    uint8_t calc_mac[32];
    ZTA_HMAC_SHA256(key, key_len, buf, ZTA_HEADER_AUTH_LEN, calc_mac);

    if (!ZTA_ConstTimeEqual(calc_mac, buf + ZTA_HEADER_AUTH_LEN, ZTA_HMAC_LEN)) {
        *out_reason = "TE09_MAC";
        return 0;
    }
    if ((uint32_t)time(NULL) > expiry) {
        *out_reason = "TE09_EXPIRED";
        return 0;
    }
    if (!ZTA_CheckAndUpdateReplay(src_id, seq)) {
        *out_reason = "TE09_REPLAY";
        return 0;
    }

    /* [Mode 2] TE-04: Attribute-Based Dynamic Access Control (Role vs MsgID) */
    uint16_t msg_id = ((uint16_t)buf[0] << 8) | buf[1];
    uint8_t  role   = buf[12];
    if (msg_id == 0x1880 && role != 0x01) {
        *out_reason = "TE04_ABAC";
        return 0;
    }
#endif

#if ZTA_PHASE_MODE >= 3
    /* [Mode 3] TE-15: Generalized Autonomous Software Isolation during LOS */
    uint8_t los_state = buf[15];
    if (los_state == 1) {
        ZTA_SrcRateState *rs = &zta_rate_tbl[src_id];
        if (rs->quarantined) {
            *out_reason = "TE15_ISOL";
            return 0;
        }
        double now = ZTA_MonotonicSec();
        if (rs->win_start_sec == 0.0 || (now - rs->win_start_sec) > ZTA_LOS_WINDOW_SEC) {
            rs->win_start_sec = now;
            rs->win_count     = 1;
        } else {
            rs->win_count++;
            if (rs->win_count > ZTA_LOS_MAX_PKTS) {
                rs->quarantined = 1;
                *out_reason = "TE15_ISOL";
                return 0;
            }
        }
    }
#endif

    return 1;
#endif
}

#endif /* ZTA_PEP_H */
