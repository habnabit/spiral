from cffi import FFI

ffi = FFI()
ffi.cdef("""

typedef uint64_t crypto_uint64;

struct curvecpr_client {
    enum {
        CURVECPR_CLIENT_PENDING,
        CURVECPR_CLIENT_INITIATING,
        CURVECPR_CLIENT_NEGOTIATED
    } negotiated;
    ...;
};

enum curvecpr_block_eofflag {
    CURVECPR_BLOCK_STREAM,
    CURVECPR_BLOCK_EOF_FAILURE,
    CURVECPR_BLOCK_EOF_SUCCESS
};

struct curvecpr_client_messager_glib;

struct curvecpr_client_messager_glib_ops {
    int (*send)(struct curvecpr_client_messager_glib *cmg, const unsigned char *buf, size_t num);
    int (*recv)(struct curvecpr_client_messager_glib *cmg, const unsigned char *buf, size_t num);
    void (*finished)(struct curvecpr_client_messager_glib *cmg, enum curvecpr_block_eofflag flag);

    int (*next_nonce)(struct curvecpr_client_messager_glib *cmg, unsigned char *destination, size_t num);
};

struct curvecpr_client_messager_glib_cf {
    /* Any extensions. */
    unsigned char my_extension[16];

    /* Curve25519 public/private keypairs. */
    unsigned char my_global_pk[32];
    unsigned char my_global_sk[32];

    /* Server configuration. */
    unsigned char their_extension[16];
    unsigned char their_global_pk[32];
    unsigned char their_domain_name[256];

    /* Messager configuration. */
    crypto_uint64 pending_maximum;
    unsigned int sendmarkq_maximum;
    unsigned int recvmarkq_maximum;

    struct curvecpr_client_messager_glib_ops ops;

    void *priv;
};

struct curvecpr_client_messager_glib {
    struct curvecpr_client_messager_glib_cf cf;
    struct curvecpr_client client;
    ...;
};

void curvecpr_client_messager_glib_new (struct curvecpr_client_messager_glib *cmg, struct curvecpr_client_messager_glib_cf *cf);
void curvecpr_client_messager_glib_dealloc (struct curvecpr_client_messager_glib *cmg);
int curvecpr_client_messager_glib_connected (struct curvecpr_client_messager_glib *cmg);
int curvecpr_client_messager_glib_send (struct curvecpr_client_messager_glib *cmg, const unsigned char *buf, size_t num);
int curvecpr_client_messager_glib_recv (struct curvecpr_client_messager_glib *cmg, const unsigned char *buf, size_t num);
unsigned char curvecpr_client_messager_glib_is_finished (struct curvecpr_client_messager_glib *cmg);
int curvecpr_client_messager_glib_finish (struct curvecpr_client_messager_glib *cmg);
int curvecpr_client_messager_glib_process_sendq (struct curvecpr_client_messager_glib *cmg);
long long curvecpr_client_messager_glib_next_timeout (struct curvecpr_client_messager_glib *cmg);

int curvecpr_util_encode_domain_name (unsigned char *destination, const char *source);

""")

C = ffi.verify("""

#include "sodium/crypto_uint64.h"
#include "curvecpr.h"
#include "curvecpr_glib.h"

""", libraries=['curvecpr', 'curvecpr-glib'])
