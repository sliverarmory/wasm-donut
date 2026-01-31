#include "../include/aplib.h"
#include <stdint.h>
#include <stddef.h>

#define HASH_BITS 15
#define HASH_SIZE (1u << HASH_BITS)
#define MAX_MATCH 4096u
#define MAX_OFFSET 65535u

struct ap_writer {
    unsigned char *dst;
    unsigned int idx;
    unsigned int tag_pos;
    unsigned int bit_idx;
};

static void ap_write_bit(struct ap_writer *w, unsigned int bit) {
    if(w->bit_idx == 0) {
        w->tag_pos = w->idx;
        w->dst[w->idx++] = 0;
    }
    if(bit) {
        w->dst[w->tag_pos] |= (unsigned char)(0x80u >> w->bit_idx);
    }
    w->bit_idx++;
    if(w->bit_idx == 8) {
        w->bit_idx = 0;
    }
}

static void ap_write_byte(struct ap_writer *w, unsigned char value) {
    w->dst[w->idx++] = value;
}

static void ap_write_gamma(struct ap_writer *w, unsigned int value) {
    int msb;
    if(value < 2) {
        value = 2;
    }
    msb = 31;
    while(msb > 0 && ((value >> msb) & 1u) == 0) {
        msb--;
    }
    for(int i = msb - 1; i >= 0; i--) {
        unsigned int bit = (value >> i) & 1u;
        ap_write_bit(w, bit);
        ap_write_bit(w, (i != 0) ? 1u : 0u);
    }
}

static unsigned int ap_hash3(const unsigned char *src, unsigned int pos) {
    return ((unsigned int)src[pos] << 8 ^ (unsigned int)src[pos + 1] << 4 ^ (unsigned int)src[pos + 2]) & (HASH_SIZE - 1);
}

unsigned int aP_pack(const void *source,
                     void *destination,
                     unsigned int length,
                     void *workmem,
                     int (*callback)(unsigned int, unsigned int, unsigned int, void *),
                     void *cbparam) {
    const unsigned char *src = (const unsigned char*)source;
    unsigned char *dst = (unsigned char*)destination;
    int *head = (int*)workmem;
    struct ap_writer w;
    unsigned int pos;
    unsigned int max_pos;
    unsigned int lwm = 0;

    (void)callback;
    (void)cbparam;

    if(source == NULL || destination == NULL || length == 0 || workmem == NULL) {
        return 0;
    }

    for(unsigned int i = 0; i < HASH_SIZE; i++) {
        head[i] = -1;
    }

    w.dst = dst;
    w.idx = 0;
    w.tag_pos = 0;
    w.bit_idx = 0;

    // first byte verbatim
    ap_write_byte(&w, src[0]);
    pos = 1;
    max_pos = length > 2 ? length - 2 : 0;

    while(pos < length) {
        unsigned int best_len = 0;
        unsigned int best_off = 0;
        unsigned int min_len = 0;

        if(pos < max_pos) {
            unsigned int h = ap_hash3(src, pos);
            int candidate = head[h];

            if(candidate >= 0) {
                unsigned int offset = pos - (unsigned int)candidate;
                if(offset > 0 && offset <= MAX_OFFSET) {
                    unsigned int max_len = length - pos;
                    if(max_len > MAX_MATCH) {
                        max_len = MAX_MATCH;
                    }

                    unsigned int l = 0;
                    while(l < max_len && src[candidate + l] == src[pos + l]) {
                        l++;
                    }

                    if(offset < 128) {
                        min_len = 4;
                    } else if(offset >= 32000) {
                        min_len = 4;
                    } else if(offset >= 1280) {
                        min_len = 3;
                    } else {
                        min_len = 2;
                    }

                    if(l >= min_len) {
                        best_len = l;
                        best_off = offset;
                    }
                }
            }

            head[h] = (int)pos;
        }

        if(best_len != 0) {
            unsigned int adj = 0;
            unsigned int len_code;
            unsigned int offs_code;

            ap_write_bit(&w, 1);
            ap_write_bit(&w, 0);

            offs_code = (best_off >> 8) + (lwm ? 2u : 3u);
            ap_write_gamma(&w, offs_code);
            ap_write_byte(&w, (unsigned char)(best_off & 0xFF));

            if(best_off >= 32000) {
                adj++;
            }
            if(best_off >= 1280) {
                adj++;
            }
            if(best_off < 128) {
                adj += 2;
            }
            len_code = best_len - adj;
            if(len_code < 2) {
                len_code = 2;
            }
            ap_write_gamma(&w, len_code);

            for(unsigned int i = 1; i < best_len; i++) {
                if(pos + i < max_pos) {
                    unsigned int h = ap_hash3(src, pos + i);
                    head[h] = (int)(pos + i);
                }
            }

            pos += best_len;
            lwm = 1;
        } else {
            ap_write_bit(&w, 0);
            ap_write_byte(&w, src[pos]);
            pos++;
            lwm = 0;
        }
    }

    // termination sequence: bits 1,1,0 then offs=0
    ap_write_bit(&w, 1);
    ap_write_bit(&w, 1);
    ap_write_bit(&w, 0);
    ap_write_byte(&w, 0);

    return w.idx;
}

unsigned int aP_workmem_size(unsigned int inputsize) {
    (void)inputsize;
    return (unsigned int)(HASH_SIZE * sizeof(int));
}

unsigned int aP_max_packed_size(unsigned int inputsize) {
    return inputsize + (inputsize / 8) + 16;
}
