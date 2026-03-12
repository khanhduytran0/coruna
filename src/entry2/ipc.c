/*
 * ipc.c - Mach IPC messaging layer
 *
 * Decompiled from entry2_type0x0f.dylib offsets 0xa6b8–0xacb8
 *
 * All communication between entry2 and the bootstrap/type0x09 happens
 * through Mach messages. This layer handles send/recv with timeouts,
 * port allocation, and response validation.
 */

#include "entry2.h"
#include <mach/mach.h>
#include <stdlib.h>
#include <string.h>

/* ── e2_send_msg (0xa820) ────────────────────────────────────────── *
 * Sends a Mach message to a port with optional reply port.
 *
 * Message layout (0x20 bytes):
 *   [0x00] msg_size | msg_bits     (0x13 or 0x1413 depending on reply_port)
 *   [0x04] unused
 *   [0x08] remote_port | local_port
 *   [0x10] <from constant pool>     (voucher/id)
 *   [0x18] stage | extra
 *   [0x1c] final
 */
kern_return_t e2_send_msg(mach_port_t port, uint32_t msg_id,
                          mach_port_t reply_port, uint32_t extra,
                          uint32_t final)
{
    if (port + 1 < 2) {
        /* port is 0 or MACH_PORT_NULL — can't send */
        return E2_ERR_MACH_MSG - 0xFFE;  /* 0x0001F039 */
    }

    /* Build the message on stack (0x20 bytes) */
    struct {
        uint32_t bits;           /* MACH_MSGH_BITS */
        uint32_t size;           /* 0x20 */
        mach_port_t remote;
        mach_port_t local;
        uint64_t voucher;        /* from constant pool at 0x1ef60 */
        uint32_t stage;
        uint32_t extra;
    } msg;

    memset(&msg, 0, sizeof(msg));

    /* If reply_port is valid, include MACH_MSG_TYPE_MAKE_SEND for reply */
    uint32_t bits = (reply_port + 1 > 1) ? 0x1413 : 0x13;
    msg.bits = bits;
    msg.size = 0x20;
    msg.remote = port;
    msg.local = reply_port;
    /* voucher loaded from literal pool */
    msg.stage = msg_id;
    msg.extra = extra;

    kern_return_t kr = mach_msg(
        (mach_msg_header_t *)&msg,
        MACH_SEND_MSG,           /* option = 0x11 (send + timeout) */
        0x20,                    /* send_size */
        0,                       /* rcv_size = 0x64 */
        port,                    /* rcv_name */
        100,                     /* timeout = 100ms */
        MACH_PORT_NULL            /* notify */
    );

    if (kr == KERN_SUCCESS) {
        return 0;
    }
    if (kr == 0x10) {
        /* MACH_SEND_TIMED_OUT — specific handling */
        return E2_ERR_MACH_MSG;
    }
    if (kr == MACH_SEND_INVALID_DEST) {
        return E2_ERR_MACH_MSG - 1;
    }
    return E2_ERR_MACH_MSG;
}

/* ── e2_recv_msg (0xab30) ────────────────────────────────────────── *
 * Receives a Mach message on a port with optional timeout.
 *
 * Allocates a receive buffer, validates the response header,
 * and returns the full message to the caller.
 */
kern_return_t e2_recv_msg(mach_port_t port, uint32_t max_size,
                          uint32_t options, uint32_t timeout,
                          void **out, uint32_t *out_size)
{
    if (max_size < 0x18) return E2_ERR_NULL;
    if (!out)            return E2_ERR_NULL;
    if (!out_size)       return E2_ERR_NULL;

    uint32_t buf_size = max_size + 8;
    void *buf = calloc(1, buf_size);
    if (!buf) return E2_ERR_ALLOC;

    /* Compose mach_msg option bits */
    uint32_t msg_option = options | MACH_RCV_MSG;  /* 0x102 */

    kern_return_t kr = mach_msg(
        (mach_msg_header_t *)buf,
        msg_option,
        0,                       /* send_size */
        buf_size,                /* rcv_size */
        port,                    /* rcv_name */
        timeout,
        MACH_PORT_NULL
    );

    /* Handle MACH_RCV_TOO_LARGE (0x10004004) — message didn't fit */
    if (kr == 0x10004004) {
        uint32_t actual_size = ((mach_msg_header_t *)buf)->msgh_size;
        if (actual_size - 0x18 > 0x063FFFE8) {
            /* Absurdly large — reject */
            *out = NULL;
            *out_size = actual_size;
            /* Send back a discard reply */
            mach_msg((mach_msg_header_t *)buf, MACH_RCV_MSG,
                     0, buf_size, port, 0, 0);
            goto fail;
        }
        *out = NULL;
        *out_size = actual_size;
        goto fail;
    }

    /* Handle MACH_RCV_TIMED_OUT (0x10004003) */
    if (kr == 0x10004003) {
        goto fail;
    }

    if (kr != KERN_SUCCESS) {
        /* Check for interrupt-like errors (0x1000400C, 0x10004008) */
        uint32_t masked = kr & ~0x4;
        if (masked == 0x10004008) {
            mach_msg_destroy((mach_msg_header_t *)buf);
        }
        goto fail;
    }

    /* Validate response size */
    uint32_t resp_size = ((mach_msg_header_t *)buf)->msgh_size;
    if (resp_size < 0x18 || resp_size > max_size) {
        mach_msg_destroy((mach_msg_header_t *)buf);
        goto fail;
    }

    /* Success — transfer ownership to caller */
    *out = buf;
    *out_size = resp_size;
    return KERN_SUCCESS;

fail:
    bzero(buf, buf_size);
    free(buf);
    return kr ? kr : E2_ERR_IPC_BASE;
}

/* ── e2_send_recv_msg (0xa6b8) ───────────────────────────────────── *
 * Full round-trip: allocate reply port, send request, receive response.
 *
 * This is the primary IPC function used by the runtime context fetch
 * and all krw operations.
 */
kern_return_t e2_send_recv_msg(mach_port_t port, uint32_t msg_id,
                               uint32_t flags, void **reply,
                               uint32_t *reply_size)
{
    if (port + 1 < 2 || !reply || !reply_size) {
        if (port + 1 > 1)
            return E2_ERR_IPC_BASE + 0x16;
        return E2_ERR_NULL;
    }

    /* Allocate a receive right for the reply */
    mach_port_t reply_port = MACH_PORT_NULL;
    kern_return_t kr = mach_port_allocate(
        mach_task_self(),
        MACH_PORT_RIGHT_RECEIVE,
        &reply_port
    );
    if (kr != KERN_SUCCESS)
        return E2_ERR_IPC_BASE;

    /* Send the request with reply port */
    kr = e2_send_msg(port, msg_id, reply_port, flags, 0);
    if (kr != KERN_SUCCESS)
        goto cleanup;

    if (reply_port + 1 < 2) {
        kr = E2_ERR_NULL;
        goto cleanup;
    }

    /* Wait for reply with 30-second timeout */
    void *response = NULL;
    uint32_t resp_size = 0;
    kr = e2_recv_msg(reply_port, 0x18, 4, 30000, &response, &resp_size);

    /* On timeout (0x1E03B), retry without timeout */
    if (kr == (E2_ERR_IPC_BASE + 0x18)) {
        kr = e2_recv_msg(reply_port, resp_size, 0, 0, &response, &resp_size);
    }

    if (kr == KERN_SUCCESS) {
        *reply = response;
        *reply_size = resp_size;
    }

cleanup:
    /* Destroy the reply port */
    mach_port_mod_refs(mach_task_self(), reply_port,
                       MACH_PORT_RIGHT_RECEIVE, -1);
    return kr;
}

/* ── e2_get_runtime_context (0xa908) ─────────────────────────────── *
 * Sends msg_id=8 to the bootstrap port and receives the runtime
 * context, which includes container data and connection info.
 *
 * Response validation:
 *   - Size >= 0x40
 *   - msg_type (offset 0x14) == 1
 *   - flags (offset 0x00) bit 31 must be clear
 */
kern_return_t e2_get_runtime_context(uint32_t stage,
                                     ipc_response_t **out,
                                     uint32_t *out_size)
{
    if (!out || !out_size)
        return E2_ERR_NULL;

    void *response = NULL;
    uint32_t resp_size = 0;

    kern_return_t kr = e2_send_recv_msg(stage, 8, 0, &response, &resp_size);
    if (kr != KERN_SUCCESS)
        return kr;

    /* Validate response */
    if (resp_size < 0x40 || !response)
        goto invalid;

    ipc_response_t *resp = (ipc_response_t *)response;

    if (resp->msg_type != 1)
        goto invalid;

    if (resp->field_00 & 0x80000000)
        goto invalid;

    /* Success */
    *out = resp;
    *out_size = resp_size;
    return KERN_SUCCESS;

invalid:
    if (response) {
        mach_msg_destroy((mach_msg_header_t *)response);
        bzero(response, resp_size);
        free(response);
    }
    return E2_ERR_MSG_INVALID;
}
