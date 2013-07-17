from cffi import FFI

ffi = FFI()
ffi.cdef("""

struct curvecpr_session {
    /* Any extensions. */
    unsigned char their_extension[16];

    /* Curve25519 public/private keypairs. */
    unsigned char their_global_pk[32];

    /* These will be automatically generated and/or filled as needed. */

    /* Curve25519 public/private keypairs. */
    unsigned char my_session_pk[32];
    unsigned char my_session_sk[32];

    unsigned char their_session_pk[32];

    /* Calculated encryption keys. */
    unsigned char my_global_their_global_key[32];
    unsigned char my_global_their_session_key[32];
    unsigned char my_session_their_global_key[32];
    unsigned char my_session_their_session_key[32];

    /* Server-specific data. */
    unsigned char my_domain_name[256];

    /* Private data. */
    void *priv;

    ...;
};

struct curvecpr_client;

struct curvecpr_client_ops {
    int (*send)(struct curvecpr_client *client, const unsigned char *buf, size_t num);
    int (*recv)(struct curvecpr_client *client, const unsigned char *buf, size_t num);

    int (*next_nonce)(struct curvecpr_client *client, unsigned char *destination, size_t num);
};

struct curvecpr_client_cf {
    /* Any extensions. */
    unsigned char my_extension[16];

    /* Curve25519 public/private keypairs. */
    unsigned char my_global_pk[32];
    unsigned char my_global_sk[32];

    /* Server configuration. */
    unsigned char their_extension[16];
    unsigned char their_global_pk[32];
    unsigned char their_domain_name[256];

    struct curvecpr_client_ops ops;

    void *priv;
};

struct curvecpr_client {
    struct curvecpr_client_cf cf;
    struct curvecpr_session session;

    enum {
        CURVECPR_CLIENT_PENDING,
        CURVECPR_CLIENT_INITIATING,
        CURVECPR_CLIENT_NEGOTIATED
    } negotiated;
    unsigned char negotiated_vouch[64];
    unsigned char negotiated_cookie[96];
};

void curvecpr_client_new (struct curvecpr_client *client, const struct curvecpr_client_cf *cf);
int curvecpr_client_connected (struct curvecpr_client *client);
int curvecpr_client_recv (struct curvecpr_client *client, const unsigned char *buf, size_t num);
int curvecpr_client_send (struct curvecpr_client *client, const unsigned char *buf, size_t num);

""")

C = ffi.verify("""

#include "sodium/crypto_uint64.h"
#include "curvecpr.h"

""", libraries=['curvecpr'])
