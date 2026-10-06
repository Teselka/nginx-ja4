#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_list.h>
#include <ngx_string.h>
#include <stdint.h>

#include <ngx_http_ssl_module.h> // ngx_http_ssl_module

#include <inttypes.h>

#include <arpa/inet.h>
#include <sys/socket.h>

#define NGX_JA4_HAVE_JA4O
#define NGX_JA4_HAVE_JA4T

#ifdef NGX_JA4_HAVE_JA4T
#if defined(__has_include) && __has_include(<netinet/tcp.h>)
#include <netinet/tcp.h>
#else
#error "No <netinet/tcp.h>"
#endif
#endif

#define ngx_ja4_log_debug(log, err, ...) ngx_log_error(NGX_LOG_DEBUG, log, err, __VA_ARGS__)

extern ngx_module_t ngx_http_ja4_module;
static int ngx_ja4_ssl_data_index = -1;

// t13d1516h2 + _ + 8daaf6152771 + _ + 14f25f0c9e96 + '\0'
// 10 + 1 + 12 + 1 + 12 + 1
#define NGX_JA4_TLS_LENGTH 37
#define NGX_JA4_TLS_B_POS 11
#define NGX_JA4_TLS_C_POS 24

struct ngx_ja4_ssl_data_t
{
    char ja4_buf[NGX_JA4_TLS_LENGTH];

#ifdef NGX_JA4_HAVE_JA4O
    char ja4o_buf[NGX_JA4_TLS_LENGTH];
#endif
};

#ifdef NGX_JA4_HAVE_JA4T

// 65535 + _ + 2-1-3-1-1-4-34 + _ + 65535 + _ + 8 + '\0'
// 5 + 1 + (3 * kinds_len) + 1 + 5 + 1 + 3 + 1
#define NGX_JA4_TCP_BASE_LENGTH 17

#define NGX_JA4_TCP_MAX_OPTIONS 10

// 10 options are fine i guess
#define NGX_JA4_TCP_MAX_LENGTH (NGX_JA4_TCP_BASE_LENGTH + (NGX_JA4_TCP_MAX_OPTIONS * 3))

struct ngx_ja4_tcp_data_t
{
    char ja4t_buf[NGX_JA4_TCP_MAX_LENGTH];
};
#endif

struct ngx_ja4_srv_conf_header_t
{
    ngx_str_t name;
    ngx_str_t lowcase;
};

struct ngx_ja4_srv_conf_t
{
    struct ngx_ja4_srv_conf_header_t ja4;
#ifdef NGX_JA4_HAVE_JA4O
    struct ngx_ja4_srv_conf_header_t ja4o;
#endif
#ifdef NGX_JA4_HAVE_JA4T
    struct ngx_ja4_srv_conf_header_t ja4t;
#endif
};

#ifdef NGX_JA4_HAVE_JA4T
static int ngx_ja4_tcp_syn_calc(ngx_connection_t *c, struct ngx_ja4_tcp_data_t* data, uint8_t* syn, size_t syn_len)
{
    size_t ip_size;
    uint8_t ip_type;
    size_t off;
    uint16_t window_size;
    uint8_t* tcp;
    uint8_t* opts;
    uint8_t* kinds;
    size_t kinds_len;
    size_t opts_len;
    uint16_t mss;
    uint8_t scale;
    size_t i;

    if (syn_len < 1)
        return NGX_ERROR;
    
    ip_type = syn[0] >> 4;
    if (ip_type == 4)
        ip_size = (syn[0] & 0x0f) * 4;
    else if (ip_type == 6)
        ip_size = 40;
    else
        return NGX_ERROR;

    if (ip_size < 20 || ip_size + 20 > syn_len)
        return NGX_ERROR;

    off = (syn[ip_size + 12] >> 4) * 4;
    if (off < 20 || ip_size + off > syn_len)
        return NGX_ERROR;

    tcp = syn + ip_size;
    opts = tcp + 20;
    opts_len = off - 20;

    window_size = ntohs(*(uint16_t*)(tcp + 14));
    mss = 0;
    scale = 0;

    kinds = (uint8_t*)alloca(opts_len);
    kinds_len = 0;
    for (i = 0; i < opts_len;) 
    {
        uint8_t kind = opts[i];

        if (kind <= 99)
            kinds[kinds_len++] = kind;

        if (kind == 0)
            break;

        if (kind == 1) {
            ++i;
            continue;
        }

        if (i + 1 >= opts_len)
            return NGX_ERROR;

        uint8_t len = *(uint8_t*)(opts + i + 1);
        if (i + len > opts_len || len < 2)
            return NGX_ERROR;

        if (kind == 2) {
            if (len != 4)
                return NGX_ERROR;

            mss = htons(*(uint16_t*)(opts + i + 2));
        }
        else if (kind == 3) {
            if (len != 3)
                return NGX_ERROR;

            scale = *(uint8_t*)(opts + i + 2);
        }
        
        i += len;
    }

    if (kinds_len > NGX_JA4_TCP_MAX_OPTIONS) {
        ngx_ja4_log_debug(c->pool->log, 0, "ja4: too much syn options: %i", (ngx_int_t)kinds_len);
        return NGX_ERROR;
    }

    char* kbuf = alloca(3 * kinds_len);
    int klen = 0;
    for (i = 0; i < kinds_len; i++) 
    {
        uint8_t kind = kinds[i];

        if (kind < 10) {
            kbuf[klen] = '0' + kinds[i];
            kbuf[klen+1] = '-';
            klen += 2;
        }
        else {
            kbuf[klen] = '0' + (kind - (kind % 10)) / 10;
            kbuf[klen+1] = '0' + (kind % 10);
            kbuf[klen+2] = '-';
            klen += 3;
        }
    }

    if (klen > 0)
        kbuf[--klen] = '\0';

    sprintf(data->ja4t_buf, "%" PRIu16 "_%.*s_%" PRIu16 "_%" PRIu8, window_size, klen, kbuf, mss, scale);
    ngx_ja4_log_debug(c->pool->log, 0, "%s", data->ja4t_buf);

    return NGX_OK;
}
#endif

static ngx_int_t ngx_ja4_http_post_read_handler(ngx_http_request_t *r)
{
    ngx_uint_t i;
    ngx_list_part_t *part;
    ngx_table_elt_t *h;
    ngx_table_elt_t *header;
    ngx_connection_t *c;
    struct ngx_ja4_srv_conf_t *conf = ngx_http_get_module_srv_conf(r, ngx_http_ja4_module);
    struct ngx_ja4_ssl_data_t* data;

    struct ngx_ja4_srv_conf_header_t *ja4 = &conf->ja4;
#ifdef NGX_JA4_HAVE_JA4O
    struct ngx_ja4_srv_conf_header_t *ja4o = &conf->ja4o;
#endif
#ifdef NGX_JA4_HAVE_JA4T
    struct ngx_ja4_srv_conf_header_t *ja4t = &conf->ja4t;
#endif

    c = r->connection;

    if (conf->ja4.name.data == NULL
#ifdef NGX_JA4_HAVE_JA4O
        && conf->ja4o.name.data == NULL
#endif
#ifdef NGX_JA4_HAVE_JA4T
        && conf->ja4t.name.data == NULL
#endif
    )
        return NGX_DECLINED;
    
    for (part = &r->headers_in.headers.part; part; part = part->next) 
    {
        h = part->elts;

        for (i = 0; i < part->nelts; i++) 
        {
            header = &h[i];
            
            if (header->key.len == ja4->lowcase.len && ngx_memcmp(header->lowcase_key, ja4->lowcase.data, ja4->lowcase.len) == 0)
                header->hash = 0;
#ifdef NGX_JA4_HAVE_JA4O
            else if (header->key.len == ja4o->lowcase.len && ngx_memcmp(header->lowcase_key, ja4o->lowcase.data, ja4o->lowcase.len) == 0)
                header->hash = 0;
#endif
#ifdef NGX_JA4_HAVE_JA4T
            else if (header->key.len == ja4t->lowcase.len && ngx_memcmp(header->lowcase_key, ja4t->lowcase.data, ja4t->lowcase.len) == 0)
                header->hash = 0;
#endif
        }
    }

#ifdef NGX_JA4_HAVE_JA4T
    if (conf->ja4t.name.data != NULL && c->type == SOCK_STREAM && !c->quic)
    {
        uint8_t syn[256];
        socklen_t len = sizeof(syn);
        int res = getsockopt(c->fd, IPPROTO_TCP, TCP_SAVED_SYN, syn, &len);
        if (res >= 0) 
        {
            struct ngx_ja4_tcp_data_t* tcp_data = ngx_palloc(r->pool, sizeof(struct ngx_ja4_tcp_data_t));
            if (tcp_data && ngx_ja4_tcp_syn_calc(c, tcp_data, syn, len) == NGX_OK)
            {
                header = ngx_list_push(&r->headers_in.headers);
                if (header == NULL)
                    return NGX_ERROR;

                ngx_memzero(header, sizeof(*header));
                header->hash = 1;
                header->key = conf->ja4t.name;
                header->lowcase_key = conf->ja4t.lowcase.data;
                header->value.data = (u_char*)tcp_data->ja4t_buf;
                header->value.len = strlen(tcp_data->ja4t_buf);
            }
        }
        else {
            ngx_ja4_log_debug(c->pool->log, ngx_errno, "ja4t: getsockopt(TCP_SAVED_SYN)");
        }
    }
#endif

    if (c->ssl == NULL || c->ssl->connection == NULL)
        return NGX_DECLINED;

    data = SSL_get_ex_data(c->ssl->connection, ngx_ja4_ssl_data_index);
    if (data == NULL)
        return NGX_DECLINED;

    if (ja4->name.data)
    {
        header = ngx_list_push(&r->headers_in.headers);
        if (header == NULL)
            return NGX_ERROR;

        ngx_memzero(header, sizeof(*header));
        header->hash = 1;
        header->key = conf->ja4.name;
        header->lowcase_key = conf->ja4.lowcase.data;
        header->value.data = (u_char*)data->ja4_buf;
        header->value.len = NGX_JA4_TLS_LENGTH - 1;
    }

#ifdef NGX_JA4_HAVE_JA4O
    if (ja4o->name.data)
    {
        header = ngx_list_push(&r->headers_in.headers);
        if (header == NULL)
            return NGX_ERROR;

        ngx_memzero(header, sizeof(*header));
        header->hash = 1;
        header->key = conf->ja4o.name;
        header->lowcase_key = conf->ja4o.lowcase.data;
        header->value.data = (u_char*)data->ja4o_buf;
        header->value.len = NGX_JA4_TLS_LENGTH - 1;
    }
#endif

    return NGX_DECLINED;
}

static ngx_int_t ngx_ja4_sub_cmp_u16(const void *one, const void *two)
{
    return *(uint16_t*)one - *(uint16_t*)two;
}

#define tohexprint(c) (unsigned char)(c <= 9 ? '0' + c : 'a' + c - 10)

static inline void ngx_ja4_toprint_list(unsigned char* p, uint8_t c0, uint8_t c1)
{
    uint8_t b;
    b = (c0 & 0xf0) >> 4;
    *p++ = tohexprint(b);
    b = c0 & 0x0f;
    *p++ = tohexprint(b);

    b = (c1 & 0xf0) >> 4;
    *p++ = tohexprint(b);
    b = c1 & 0x0f;
    *p++ = tohexprint(b);

    *p++ = ',';
}

static inline void ngx_ja4_toprint_byte(unsigned char* p, uint8_t c0)
{
    uint8_t b;
    b = (c0 & 0xf0) >> 4;
    *p++ = tohexprint(b);
    b = c0 & 0x0f;
    *p++ = tohexprint(b);
}

static size_t ngx_ja4_add_print_sigalgs(unsigned char* cbuf, uint16_t* sigalgs, size_t sigalgs_num)
{
    size_t i;
    size_t ci = 0;

    for (i = 0; i < sigalgs_num; i++) {
        uint16_t alg = *(uint16_t*)(sigalgs + i);
        ngx_ja4_toprint_list(cbuf + ci, alg & 0xff, (alg & 0xff00) >> 8);
        ci += 5;
    }

    if (ci > 0)
        cbuf[--ci] = '\0';

    return ci;
}

static int ngx_ja4_tls_calc(SSL *ssl, ngx_connection_t* c, struct ngx_ja4_ssl_data_t* data)
{
    uint16_t tls_version;
    const unsigned char *ciphers;
    size_t ciphers_len;
    size_t ciphers_num;
    size_t num_exts;
    size_t real_num_exts;
    size_t i;
    char* ja4_buf = &data->ja4_buf[0];
#ifdef NGX_JA4_HAVE_JA4O
    char* ja4o_buf = &data->ja4o_buf[0];
#endif
    unsigned char* cbuf;
    uint16_t* sortbuf;
    size_t ci;
    uint8_t sha256_buf[32];
    uint16_t* exts_sigalgs;
    const unsigned char* raw_sigalgs;
    size_t sigalgs_num;
    const unsigned char *alpn;
    size_t alpn_num;
    size_t alpn_len;

    if (c->type == SOCK_DGRAM)
        ja4_buf[0] = 'q';
    else
        ja4_buf[0] = 't';

    tls_version = 0;

    if (SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_supported_versions, (const unsigned char**)&cbuf, &ci) == 1) 
    {
        if (ci < 3 || cbuf[0] != ci - 1 || cbuf[0] % 2 != 0)
            return NGX_DECLINED;

        for (i = 1; i + 1 < ci; i += 2) {
            uint16_t v = (cbuf[i] << 8) | cbuf[i + 1];
            if (v >= TLS1_VERSION && 
#ifdef TLS1_4_VERSION
                v <= TLS1_4_VERSION
#else
                v <= TLS1_3_VERSION
#endif 
                && v > tls_version) 
            {
                tls_version = v;
            }
        }
    }
    else {
        tls_version = SSL_client_hello_get0_legacy_version(ssl);
    }

    switch (tls_version) 
    {
#ifdef TLS1_4_VERSION
    case TLS1_4_VERSION: ja4_buf[1] = '1'; ja4_buf[2] = '4'; break;
#endif
    case TLS1_3_VERSION: ja4_buf[1] = '1'; ja4_buf[2] = '3'; break;
    case TLS1_2_VERSION: ja4_buf[1] = '1'; ja4_buf[2] = '2'; break;
    case TLS1_1_VERSION: ja4_buf[1] = '1'; ja4_buf[2] = '1'; break;
    case TLS1_VERSION: ja4_buf[1] = '1'; ja4_buf[2] = '0'; break;
    default: return NGX_DECLINED;
    }

    if (SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_server_name, NULL, NULL) == 1)
        ja4_buf[3] = 'd';
    else
        ja4_buf[3] = 'i';

    ciphers_len = SSL_client_hello_get0_ciphers(ssl, &ciphers);
    if (ciphers_len % 2)
        return NGX_DECLINED;

    cbuf = ngx_palloc(c->pool, ciphers_len * 5);
    if (cbuf == NULL)
        return NGX_DECLINED;

    sortbuf = ngx_palloc(c->pool, ciphers_len);
    if (sortbuf == NULL)
        return NGX_DECLINED;

    ciphers_num = 0;
    ci = 0;
    for (i = 0; i + 1 < ciphers_len; i += 2) {
        uint8_t c0 = ciphers[i];
        uint8_t c1 = ciphers[i+1];

        uint16_t c = ((uint16_t)c0 << 8) | (uint16_t)c1;
        if ((c & 0x0f0f) == 0x0a0a && c0 == c1)
            continue;

#ifdef NGX_JA4_HAVE_JA4O
        ngx_ja4_toprint_list(cbuf + ci, c0, c1);
        ci += 5;
#endif

        sortbuf[ciphers_num] = c;

        ++ciphers_num;
    }

#ifdef NGX_JA4_HAVE_JA4O
    if (ci > 0)
        cbuf[--ci] = '\0';

    ngx_ja4_log_debug(c->log, 0, "ja4o_r_b: %*s", ci, cbuf);
#endif

    if (ciphers_num > 99)
        return NGX_DECLINED;

    ja4_buf[4] = '0' + (ciphers_num - (ciphers_num % 10)) / 10;
    ja4_buf[5] = '0' + (ciphers_num % 10);

    if (SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_application_layer_protocol_negotiation, &alpn, &alpn_num) == 0 || alpn_num < 3) {
        alpn = NULL;
        alpn_len = 0;
    }
    else {
        alpn_len = *(uint8_t*)(alpn + 2);
        if (alpn_len > alpn_num - 3) {
            alpn = NULL;
            alpn_len = 0;
        }
        else {
            alpn += 3;
        }
    }

    if (alpn != NULL && alpn_len >= 2 && isprint(alpn[0]) && isprint(alpn[alpn_len-1]))
    {
        ja4_buf[8] = alpn[0];
        ja4_buf[9] = alpn[alpn_len-1];
    }
    else {
        alpn = NULL;
    }

    if (alpn == NULL)
        *(uint16_t*)(ja4_buf + 8) = 0x3030;

    // ciphers
#ifdef NGX_JA4_HAVE_JA4O
    if (ci > 0)
        SHA256(cbuf, ci, sha256_buf);
    else
        ngx_memzero(sha256_buf, sizeof(sha256_buf));

    ja4o_buf[NGX_JA4_TLS_B_POS-1] = '_';

    ci = NGX_JA4_TLS_B_POS;
    for (i = 0; i < 6; i++) {
        uint8_t c0 = sha256_buf[i];
        ngx_ja4_toprint_byte((unsigned char*)ja4o_buf + ci, c0);
        ci += 2;
    }

    ngx_ja4_log_debug(c->log, 0, "ja4o_b: %*s", ci - NGX_JA4_TLS_B_POS, ja4o_buf + NGX_JA4_TLS_B_POS);
#endif

    ngx_sort(sortbuf, ciphers_num, sizeof(uint16_t), ngx_ja4_sub_cmp_u16);

    ci = 0;
    for (i = 0; i < ciphers_num; i++) {
        uint16_t b = sortbuf[i];
        ngx_ja4_toprint_list(cbuf + ci, (b & 0xff00) >> 8, b & 0xff);
        ci += 5;
    }

    if (ci > 0)
        cbuf[--ci] = '\0';

    if (ci > 0)
        SHA256(cbuf, ci, sha256_buf);
    else
        ngx_memzero(sha256_buf, sizeof(sha256_buf));

    ja4_buf[NGX_JA4_TLS_B_POS-1] = '_';

    ci = NGX_JA4_TLS_B_POS;
    for (i = 0; i < 6; i++) {
        uint8_t c0 = sha256_buf[i];
        ngx_ja4_toprint_byte((unsigned char*)ja4_buf + ci, c0);
        ci += 2;
    }

    // extensions
    if (!SSL_client_hello_get_extension_order(ssl, NULL, &num_exts))
        num_exts = 0;

    if (SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_signature_algorithms, &raw_sigalgs, &sigalgs_num) == 1 && sigalgs_num > 2) {
        uint16_t list_len = ntohs(*(uint16_t*)raw_sigalgs);
        if ((size_t)list_len + 2 > sigalgs_num || list_len % 2)
            return NGX_DECLINED;

        exts_sigalgs = ngx_palloc(c->pool, sizeof(uint16_t) * (num_exts + list_len / 2));
        if (exts_sigalgs == NULL)
            return NGX_DECLINED;

        sigalgs_num = 0;
        for (i = 0; i < list_len; i += 2) {
            *(exts_sigalgs + num_exts + sigalgs_num) = *((uint16_t*)raw_sigalgs + 1 + sigalgs_num);
            ++sigalgs_num;
        }
    }
    else {
        exts_sigalgs = NULL;
        sigalgs_num = 0;
    }

    if (!exts_sigalgs) {
        exts_sigalgs = ngx_palloc(c->pool, sizeof(uint16_t) * num_exts);
        if (exts_sigalgs == NULL)
            return NGX_DECLINED;
    }
    
    ngx_pfree(c->pool, cbuf);
    cbuf = ngx_palloc(c->pool, ((num_exts + sigalgs_num) * 5) + 1);
    if (cbuf == NULL)
        return NGX_DECLINED;

    if (SSL_client_hello_get_extension_order(ssl, exts_sigalgs, &num_exts) != 1)
        return NGX_DECLINED;

    ci = 0;
    for (i = 0; i < num_exts; i++) {
        uint16_t b = exts_sigalgs[i];
        if (!((b & 0x0f0f) == 0x0a0a && (b >> 8) == (b & 0xff)))
            exts_sigalgs[ci++] = b;
    }

    real_num_exts = ci;

    if (real_num_exts > 99)
        return NGX_DECLINED;

    ja4_buf[6] = '0' + (real_num_exts - (real_num_exts % 10)) / 10;
    ja4_buf[7] = '0' + (real_num_exts % 10);

#ifdef NGX_JA4_HAVE_JA4O
    ci = 0;
    for (i = 0; i < real_num_exts; i++) {
        uint16_t b = exts_sigalgs[i];
        ngx_ja4_toprint_list(cbuf + ci, (b & 0xff00) >> 8, b & 0xff);
        ci += 5;
    }

    if (ci > 0)
        cbuf[--ci] = '\0';

    ngx_ja4_log_debug(c->log, 0, "ja4o_r_c1: %*s", ci, cbuf);

    if (sigalgs_num > 0)
    {
        cbuf[ci++] = '_';
        ci += ngx_ja4_add_print_sigalgs(cbuf + ci, exts_sigalgs + num_exts, sigalgs_num);
        ngx_ja4_log_debug(c->log, 0, "ja4o_r_c2: %*s", sigalgs_num * 5, cbuf + ci - sigalgs_num * 5 + 1);
    }

    SHA256(cbuf, ci, sha256_buf);

    ja4o_buf[NGX_JA4_TLS_C_POS-1] = '_';

    ci = NGX_JA4_TLS_C_POS;
    for (i = 0; i < 6; i++) {
        uint8_t c0 = sha256_buf[i];
        ngx_ja4_toprint_byte((unsigned char*)ja4o_buf + ci, c0);
        ci += 2;
    }
#endif

    ngx_sort(exts_sigalgs, real_num_exts, sizeof(uint16_t), ngx_ja4_sub_cmp_u16);

    ci = 0;
    for (i = 0; i < real_num_exts; i++) {
        uint16_t b = exts_sigalgs[i];
        if (b == 0x0000 || b == 0x0010)
            continue;
        
        ngx_ja4_toprint_list(cbuf + ci, (b & 0xff00) >> 8, b & 0xff);
        ci += 5;
    }

    if (ci > 0)
        cbuf[--ci] = '\0';
    
    ngx_ja4_log_debug(c->log, 0, "ja4_r_c1: %*s", ci, cbuf);

    if (sigalgs_num > 0)
    {
        cbuf[ci++] = '_';
        ci += ngx_ja4_add_print_sigalgs(cbuf + ci, exts_sigalgs + num_exts, sigalgs_num);
        ngx_ja4_log_debug(c->log, 0, "ja4o_r_c2: %*s", sigalgs_num * 5, cbuf + ci - sigalgs_num * 5 + 1);
    }

    SHA256(cbuf, ci, sha256_buf);

    ja4_buf[NGX_JA4_TLS_C_POS-1] = '_';

    ci = NGX_JA4_TLS_C_POS;
    for (i = 0; i < 6; i++) {
        uint8_t c0 = sha256_buf[i];
        ngx_ja4_toprint_byte((unsigned char*)ja4_buf + ci, c0);
        ci += 2;
    }

    ngx_ja4_log_debug(c->log, 0, "%*s", NGX_JA4_TLS_LENGTH-1, ja4_buf);

#ifdef NGX_JA4_HAVE_JA4O
    ngx_memcpy(ja4o_buf, ja4_buf, 11);
    ngx_ja4_log_debug(c->log, 0, "%*s", NGX_JA4_TLS_LENGTH-1, ja4o_buf);
#endif

    return NGX_OK;
}

static int ngx_ja4_client_hello_callback(SSL *ssl, int *al, void *arg)
{
    ngx_connection_t *c;
    struct ngx_ja4_ssl_data_t *data;
    int res;

    c = ngx_ssl_get_connection(ssl);

    data = SSL_get_ex_data(c->ssl->connection, ngx_ja4_ssl_data_index);
    if (data != NULL)
        return ngx_ssl_client_hello_callback(ssl, al, arg);

    if (SSL_is_tls(ssl))
    {
        data = ngx_palloc(c->pool, sizeof(struct ngx_ja4_ssl_data_t));
        if (data)
        {
            res = ngx_ja4_tls_calc(ssl, c, data);
            if (res == NGX_OK)
                SSL_set_ex_data(ssl, ngx_ja4_ssl_data_index, data);
            else {
                ngx_ja4_log_debug(c->pool->log, 0, "ja4: ngx_ja4_tls_calc fail: %i", (ngx_int_t)res);
                ngx_pfree(c->pool, data);
            }
        }
        else {
            ngx_log_error(NGX_LOG_ERR, c->pool->log, 0, "ja4: no memory for ssl data");
        }
    }

    return ngx_ssl_client_hello_callback(ssl, al, arg);
}

static ngx_int_t ngx_http_ja4_init(ngx_conf_t *cf)
{
    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "ja4: module loaded");

    ngx_http_core_main_conf_t *cmcf;
    ngx_http_handler_pt *h;
    ngx_uint_t i;
    ngx_http_ssl_srv_conf_t *sscf;
    ngx_http_core_srv_conf_t **cscfp;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_POST_READ_PHASE].handlers);
    if (h == NULL)
        return NGX_ERROR;

    *h = &ngx_ja4_http_post_read_handler;

    cscfp = cmcf->servers.elts;

    for (i = 0; i < cmcf->servers.nelts; i++) 
    {
        sscf = cscfp[i]->ctx->srv_conf[ngx_http_ssl_module.ctx_index];
        if (sscf->ssl.ctx == NULL)
            continue;

        SSL_CTX_set_client_hello_cb(sscf->ssl.ctx, &ngx_ja4_client_hello_callback, NULL);
    }

    ngx_ja4_ssl_data_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
    if (ngx_ja4_ssl_data_index <= 0) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "ja4: no available SSL data slot");
        return NGX_ERROR;
    }

    return NGX_OK;
}

static void *ngx_ja4_create_srv_conf(ngx_conf_t *cf)
{
    return ngx_pcalloc(cf->pool, sizeof(struct ngx_ja4_srv_conf_t));    
}

static char *ngx_ja4_merge_srv_conf(ngx_conf_t *cf, void *prev, void *conf)
{
    struct ngx_ja4_srv_conf_t *p = prev;
    struct ngx_ja4_srv_conf_t *c = conf;

    if (c->ja4.name.data == NULL)
        c->ja4 = p->ja4;

#ifdef NGX_JA4_HAVE_JA4O
    if (c->ja4o.name.data == NULL)
        c->ja4o = p->ja4o;
#endif

#ifdef NGX_JA4_HAVE_JA4T
    if (c->ja4t.name.data == NULL)
        c->ja4t = p->ja4t;
#endif

    return NGX_CONF_OK;
}

static char *ngx_ja4_header_set_handler(ngx_conf_t *cf, struct ngx_ja4_srv_conf_t *c, struct ngx_ja4_srv_conf_header_t* header)
{
    ngx_str_t *value = cf->args->elts; 

    if (header->name.data)
        return "duplicated";

    if (value[1].len == 0)
        return "empty";

    header->name.data = ngx_palloc(cf->pool, value[1].len);
    header->lowcase.data = ngx_palloc(cf->pool, value[1].len);
    if (header->name.data == NULL || header->lowcase.data == NULL)
        return NGX_CONF_ERROR;

    ngx_memcpy(header->name.data, value[1].data, value[1].len);
    ngx_strlow(header->lowcase.data, value[1].data, value[1].len);
    header->name.len = value[1].len;
    header->lowcase.len = value[1].len;

    return NGX_CONF_OK;
}

static char *ngx_ja4_http_header_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    struct ngx_ja4_srv_conf_t *c = conf;
    return ngx_ja4_header_set_handler(cf, c, &c->ja4);
}

static char *ngx_ja4o_http_header_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    struct ngx_ja4_srv_conf_t *c = conf;
    return ngx_ja4_header_set_handler(cf, c, &c->ja4o);
}

static char *ngx_ja4t_http_header_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    struct ngx_ja4_srv_conf_t *c = conf;
    return ngx_ja4_header_set_handler(cf, c, &c->ja4t);
}

static ngx_http_module_t ngx_http_ja4_module_ctx = 
{
    NULL,
    &ngx_http_ja4_init,
    NULL,
    NULL,
    &ngx_ja4_create_srv_conf,
    &ngx_ja4_merge_srv_conf,
    NULL,
    NULL
};

static ngx_command_t ngx_http_ja4_commands[] = 
{
    {
        ngx_string("ja4_header"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
        &ngx_ja4_http_header_set,
        NGX_HTTP_SRV_CONF_OFFSET,
        0, 
        NULL 
    },
#ifdef NGX_JA4_HAVE_JA4O
    {
        ngx_string("ja4o_header"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
        &ngx_ja4o_http_header_set,
        NGX_HTTP_SRV_CONF_OFFSET,
        0, 
        NULL 
    },
#endif
#ifdef NGX_JA4_HAVE_JA4T
    {
        ngx_string("ja4t_header"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
        &ngx_ja4t_http_header_set,
        NGX_HTTP_SRV_CONF_OFFSET,
        0, 
        NULL 
    },
#endif
    ngx_null_command
};

static ngx_int_t ngx_http_ja4_init_process(ngx_cycle_t *cycle)
{
    ngx_listening_t *ls = cycle->listening.elts;

#ifdef NGX_JA4_HAVE_JA4T
    for (ngx_uint_t i = 0; i < cycle->listening.nelts; i++) 
    {
        ngx_listening_t *s = &ls[i];
        if (s->type != SOCK_STREAM)
            continue;

        int opt = 1;
        if (setsockopt(s->fd, IPPROTO_TCP, TCP_SAVE_SYN, &opt, sizeof(opt)) < 0)
            ngx_log_error(NGX_LOG_WARN, cycle->log, ngx_errno, "ja4: failed to set TCP_SAVE_SYN for fd: %i", (ngx_int_t)s->fd);
    }
#endif

    return NGX_OK;
}

ngx_module_t ngx_http_ja4_module = 
{
    NGX_MODULE_V1,
    &ngx_http_ja4_module_ctx,
    ngx_http_ja4_commands,
    NGX_HTTP_MODULE,
    NULL,
    NULL,
    &ngx_http_ja4_init_process,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING
};
