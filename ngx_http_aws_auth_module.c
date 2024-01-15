#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

static const EVP_MD* evp_md = NULL;

#define AWS_S3_VARIABLE "s3_auth_token"
#define AWS_DATE_VARIABLE "aws_date"

static void* ngx_http_aws_auth_create_loc_conf(ngx_conf_t *cf);
static char* ngx_http_aws_auth_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t register_variable(ngx_conf_t *cf);
static char *
ngx_http_aws_auth_set_s3_bucket(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *
ngx_http_aws_auth_set_chop_prefix(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

typedef struct {
    ngx_array_t                *lengths;
    ngx_array_t                *values;
} ngx_http_aws_auth_script_t;

typedef struct {
    ngx_str_t access_key;
    ngx_str_t secret;
    ngx_str_t s3_bucket;
    ngx_str_t chop_prefix;
    ngx_http_aws_auth_script_t *s3_bucket_script;
    ngx_http_aws_auth_script_t *chop_prefix_script;
} ngx_http_aws_auth_conf_t;

static const char *signed_subresources[] = {
  "acl",
  "cors",
  "delete",
  "lifecycle",
  "location",
  "logging",
  "notification",
  "partNumber",
  "policy",
  "requestPayment",
  "response-cache-control",
  "response-content-disposition",
  "response-content-encoding",
  "response-content-language",
  "response-content-type",
  "response-expires",
  "torrent",
  "uploadId",
  "uploads",
  "versionId",
  "versioning",
  "versions",
  "website",
  NULL
};

static ngx_command_t  ngx_http_aws_auth_commands[] = {
    { ngx_string("aws_access_key"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_aws_auth_conf_t, access_key),
      NULL },

    { ngx_string("aws_secret_key"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_aws_auth_conf_t, secret),
      NULL },

    { ngx_string("s3_bucket"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_aws_auth_set_s3_bucket,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_aws_auth_conf_t, s3_bucket),
      NULL },
  
    { ngx_string("chop_prefix"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_aws_auth_set_chop_prefix,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_aws_auth_conf_t, chop_prefix),
      NULL },

      ngx_null_command
};

static ngx_http_module_t  ngx_http_aws_auth_module_ctx = {
    register_variable,                     /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_aws_auth_create_loc_conf,     /* create location configuration */
    ngx_http_aws_auth_merge_loc_conf       /* merge location configuration */
};


ngx_module_t  ngx_http_aws_auth_module = {
    NGX_MODULE_V1,
    &ngx_http_aws_auth_module_ctx,              /* module context */
    ngx_http_aws_auth_commands,                 /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static char *
ngx_http_aws_auth_set_s3_bucket(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_aws_auth_conf_t *aws_conf = conf;
    ngx_http_script_compile_t   sc;
    ngx_str_t *value;
    ngx_uint_t n;
    value = cf->args->elts;
    n = ngx_http_script_variables_count(&value[1]);

    if (n == 0) {
        // set s3_bucket as string
        aws_conf->s3_bucket.data = value[1].data;
        aws_conf->s3_bucket.len  = value[1].len;
    } else {
        //add script to compile
        aws_conf->s3_bucket_script = ngx_pcalloc(cf->pool, sizeof(ngx_http_aws_auth_script_t));
        if (aws_conf->s3_bucket_script == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

        sc.cf = cf;
        sc.source = &value[1];
        sc.lengths = &aws_conf->s3_bucket_script->lengths;
        sc.values = &aws_conf->s3_bucket_script->values;
        sc.variables = n;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (ngx_http_script_compile(&sc) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }
    return NGX_CONF_OK;
}

static char *
ngx_http_aws_auth_set_chop_prefix(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_aws_auth_conf_t *aws_conf = conf;
    ngx_http_script_compile_t   sc;
    ngx_str_t *value;
    ngx_uint_t n;
    value = cf->args->elts;
    n = ngx_http_script_variables_count(&value[1]);

    if (n == 0) {
        // set chop_prefix as string
        aws_conf->chop_prefix.data = value[1].data;
        aws_conf->chop_prefix.len  = value[1].len;
    } else {
        //add script to compile
        aws_conf->chop_prefix_script = ngx_pcalloc(cf->pool, sizeof(ngx_http_aws_auth_script_t));
        if (aws_conf->chop_prefix_script == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

        sc.cf = cf;
        sc.source = &value[1];
        sc.lengths = &aws_conf->chop_prefix_script->lengths;
        sc.values = &aws_conf->chop_prefix_script->values;
        sc.variables = n;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (ngx_http_script_compile(&sc) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }
    return NGX_CONF_OK;
}


static void *
ngx_http_aws_auth_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_aws_auth_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_aws_auth_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    return conf;    
}

static char *
ngx_http_aws_auth_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    register_variable(cf);

    ngx_http_aws_auth_conf_t *prev = parent;
    ngx_http_aws_auth_conf_t *conf = child;

    ngx_conf_merge_str_value(conf->access_key, prev->access_key, "");
    ngx_conf_merge_str_value(conf->secret, prev->secret, "");
    ngx_conf_merge_str_value(conf->chop_prefix, prev->chop_prefix, "");

    return NGX_CONF_OK;
}

static int
ngx_http_cmp_hnames(const void *one, const void *two) {
    ngx_table_elt_t *first, *second;
    int ret;
    first  = (ngx_table_elt_t *) one;
    second = (ngx_table_elt_t *) two;
    ret = ngx_strncmp(first->key.data, second->key.data, ngx_min(first->key.len, second->key.len));
    if (ret != 0){
        return ret;
    } else {
        return (first->key.len - second->key.len);
    }
}

static ngx_int_t
ngx_http_aws_auth_get_canon_headers(ngx_http_request_t *r, ngx_str_t *retstr) {
    ngx_array_t       *v;
    ngx_list_part_t   *part;
    ngx_table_elt_t   *header, *el, *h;
    ngx_uint_t        i, ch, lenall, offset;

    part = &r->headers_in.headers.part;
    header = part->elts;

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "start normalize headers");
    v = ngx_array_create(r->pool, 10, sizeof(ngx_table_elt_t));
    if (v == NULL) {
        return NGX_ERROR;
    }

    lenall = 0;
    for (i = 0; /* void */ ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (header[i].hash == 0) {
            continue;
        }

        if (ngx_strncasecmp(header[i].key.data, (u_char *) "x-amz-",  sizeof("x-amz-") - 1) == 0) {
            h = ngx_array_push(v);
            if (h == NULL) {
                return NGX_ERROR;
            }
            h->key.data = ngx_palloc(r->pool, header[i].key.len);
            for (ch = 0; ch < header[i].key.len; ch++) {
                h->key.data[ch] = ngx_tolower(header[i].key.data[ch]);
            }
            h->key.len  = header[i].key.len;
            h->value.data  = header[i].value.data;
            h->value.len  = header[i].value.len;
            lenall += h->key.len + h->value.len + 2;
            ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                "x-amz header key: %V; val: %V ",&h->key, &h->value);
            continue;
        }
    }

    h = ngx_array_push(v);
    if (h == NULL) {
        return NGX_ERROR;
    }

    ngx_str_t amz_date = ngx_string("x-amz-date");
    u_char * val  = ngx_palloc(r->pool, ngx_cached_http_time.len + 1);
    ngx_memcpy(val, ngx_cached_http_time.data, ngx_cached_http_time.len);
    h->key.data = amz_date.data;
    h->key.len  = amz_date.len;
    h->value.data  = val;
    h->value.len  = ngx_cached_http_time.len;
    lenall += h->key.len + h->value.len + 2;

    ngx_qsort(v->elts, (size_t) v->nelts, sizeof(ngx_table_elt_t), ngx_http_cmp_hnames);

    el = v->elts;
    u_char * ret = ngx_palloc(r->pool, lenall + 1);
    offset = 0;

    for (i = 0; i < v->nelts ; i++) {
        ngx_memcpy(ret + offset, el[i].key.data, el[i].key.len);
        offset += el[i].key.len;
        ngx_memcpy(ret + offset, (u_char *)":", 1);
        offset += 1;
        ngx_memcpy(ret + offset, el[i].value.data, el[i].value.len);
        offset += el[i].value.len;
        ngx_memcpy(ret + offset, (u_char *)"\n", 1);
        offset += 1;
    }
    retstr->data = ret;
    retstr->len = offset;

    return NGX_OK;
}


/* copy paste from ngx_http_arg */
ngx_int_t
ngx_http_arg2(ngx_http_request_t *r, u_char *name, size_t len, ngx_str_t *value) {
    u_char  *p, *last;
    if (r->args.len == 0) {
        return NGX_DECLINED;
    }
    p = r->args.data;
    last = p + r->args.len;
    for ( /* void */ ; p < last; p++) {
        if (p + len > last) {
            return NGX_DECLINED;
        }
        if (ngx_strncasecmp(p, name, len) != 0) {
            continue;
        }
        if (p == r->args.data || *(p - 1) == '&' || (p + len) == last || *(p + len) == '&' || *(p + len) == '=') {
            if ((p + len) < last && *(p + len) == '=') {
                value->data = p + len + 1;
                p = ngx_strlchr(p, last, '&');
                if ( p == NULL) {
                    p = r->args.data + r->args.len;
                }
                value->len = p - value->data;
            } else {
                value->len = 0;
            }
            return NGX_OK;
        }
    }
    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_aws_auth_get_canon_resource(ngx_http_request_t *r, ngx_str_t *retstr) {
    ngx_http_aws_auth_conf_t *aws_conf;
    int uri_len;
    aws_conf = ngx_http_get_module_loc_conf(r, ngx_http_aws_auth_module);
    u_char *uri = ngx_palloc(r->pool, r->uri.len * 3 + 1); // allow room for escaping
    u_char *uri_end = (u_char*) ngx_escape_uri(uri,r->uri.data, r->uri.len, NGX_ESCAPE_URI);
    *uri_end = '\0'; // null terminate

    if (aws_conf->chop_prefix.len > 0) {
        if (!ngx_strncmp(r->uri.data, aws_conf->chop_prefix.data, aws_conf->chop_prefix.len)) {
          uri += aws_conf->chop_prefix.len;
          ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
            "chop_prefix '%V' chopped from URI",&aws_conf->chop_prefix);
        } else {
          ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "chop_prefix '%V' NOT in URI",&aws_conf->chop_prefix);
        }
    }

    u_char *c_args = ngx_palloc(r->pool, r->args.len + 1); 
    u_char *c_args_cur = c_args;
    ngx_str_t arg_val;
    ngx_int_t c_args_len = 0;
    if (r->args.len > 0) {
        const char **p = signed_subresources;
        for (; *p; ++p) {
            if (ngx_http_arg2(r, (u_char *)*p, ngx_strlen((u_char *)*p), &arg_val) == NGX_OK) {
                if (c_args_cur == c_args) {
                    *c_args_cur = '?';
                } else {
                    *c_args_cur = '&';
                }
                c_args_cur += 1;
                c_args_cur = ngx_cpystrn(c_args_cur, (u_char *)*p, ngx_strlen((u_char *)*p) + 1);
                if (arg_val.len > 0) {
                    *c_args_cur = '=';
                    c_args_cur += 1;
                    ngx_memcpy(c_args_cur, arg_val.data, arg_val.len);
                    c_args_cur += arg_val.len;
                }
            }
        }
        c_args_len = c_args_cur - c_args;
        *c_args_cur = '\0';
    } 

    uri_len = ngx_strlen(uri);
    u_char *ret = ngx_palloc(r->pool, uri_len + aws_conf->s3_bucket.len + sizeof("/") + c_args_len + 1); 
    u_char *cur = ret; 
    cur = ngx_cpystrn(cur, (u_char *)"/", sizeof("/"));
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "bucket: %V", &aws_conf->s3_bucket);
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "uri:    %s", uri);
    cur = ngx_cpystrn(cur, aws_conf->s3_bucket.data, aws_conf->s3_bucket.len + 1);
    cur = ngx_cpystrn(cur, uri, uri_len + 1);
      
    if ( c_args_len ) {
        ngx_memcpy(cur, c_args, c_args_len + 1);
        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "args: %s", c_args);
    }
    *(cur+c_args_len) = '\0';
    retstr->data = ret;
    retstr->len = sizeof("/") - 1 + uri_len + aws_conf->s3_bucket.len + c_args_len;
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "normalized resources: %V", retstr);

    return NGX_OK;
}

static ngx_int_t
ngx_http_aws_auth_get_dynamic_variables(ngx_http_request_t *r){
    /* 
     * Get value for s3_bucket and chop_prefix 
    */
    ngx_http_aws_auth_conf_t *aws_conf;
    aws_conf = ngx_http_get_module_loc_conf(r, ngx_http_aws_auth_module);
    if (aws_conf->s3_bucket_script != NULL){
        if (ngx_http_script_run(r, &aws_conf->s3_bucket, aws_conf->s3_bucket_script->lengths->elts, 1,
                                aws_conf->s3_bucket_script->values->elts) == NULL) {
            return NGX_ERROR;
        }
        aws_conf->s3_bucket.len = aws_conf->s3_bucket.len -1;
    }
    if (aws_conf->chop_prefix_script != NULL){
        if (ngx_http_script_run(r, &aws_conf->chop_prefix, aws_conf->chop_prefix_script->lengths->elts, 1,
                                aws_conf->chop_prefix_script->values->elts) == NULL) {
            return NGX_ERROR;
        }
        aws_conf->chop_prefix.len = aws_conf->chop_prefix.len -1;
    }
    return NGX_OK;
}

static ngx_int_t
ngx_http_aws_auth_sgn_newline(ngx_array_t* to_sign){
    ngx_str_t         *el_sign;
    el_sign = ngx_array_push(to_sign);
    if (el_sign == NULL) {
        return NGX_ERROR;
    }
    el_sign->data = (u_char *)"\n";
    el_sign->len  = 1;
    return NGX_OK;
}

static ngx_int_t
ngx_http_aws_auth_variable_s3(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_http_aws_auth_conf_t *aws_conf;
    ngx_array_t       *to_sign;
    ngx_str_t         *el_sign, *el;
    ngx_uint_t        lenall, i;
    unsigned int      md_len;
    unsigned char     md[EVP_MAX_MD_SIZE];

    aws_conf = ngx_http_get_module_loc_conf(r, ngx_http_aws_auth_module);
    if (ngx_http_aws_auth_get_dynamic_variables(r) != NGX_OK) {
        return NGX_ERROR;
    }

    /* 
     *   This Block of code added to deal with paths that are not on the root -
     *   that is, via proxy_pass that are being redirected and the base part of 
     *   the proxy url needs to be taken off the beginning of the URI in order 
     *   to sign it correctly.
    */

    to_sign = ngx_array_create(r->pool, 10, sizeof(ngx_str_t));
    if (to_sign == NULL) {
        return NGX_ERROR;
    }

    el_sign = ngx_array_push(to_sign);
    if (el_sign == NULL) {
        return NGX_ERROR;
    }

    lenall = 0;
    el_sign->data = r->method_name.data;
    el_sign->len  = r->method_name.len;
    lenall += el_sign->len;
    ngx_http_aws_auth_sgn_newline(to_sign);

    ngx_http_variable_value_t  *val;
    val = ngx_palloc(r->pool, sizeof(ngx_http_variable_value_t));
    if (val == NULL) {
        return NGX_ENOMEM;
    }
    ngx_str_t h_name = ngx_string("http_content_md5");
    if (ngx_http_variable_unknown_header(r, val, &h_name, &r->headers_in.headers.part, sizeof("http_")-1) == NGX_OK){
        if (val->not_found == 0) {
            ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "Content-MD5: %s", val->data);
            el_sign = ngx_array_push(to_sign);
            if (el_sign == NULL) {
                return NGX_ERROR;
            }
            el_sign->data = val->data;
            el_sign->len  = val->len;
            lenall += el_sign->len;
        }
    }

    ngx_http_aws_auth_sgn_newline(to_sign);

    if (r->headers_in.content_type != NULL) {
        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "content-type: %V", &r->headers_in.content_type->value);
        el_sign = ngx_array_push(to_sign);
        if (el_sign == NULL) {
            return NGX_ERROR;
        }
        el_sign->data = r->headers_in.content_type->value.data;
        el_sign->len  = r->headers_in.content_type->value.len;
        lenall += el_sign->len;
    }
    ngx_http_aws_auth_sgn_newline(to_sign);
    ngx_str_t h_date = ngx_string("http_date");
    if (ngx_http_variable_unknown_header(r, val, &h_date, &r->headers_in.headers.part, sizeof("http_")-1) == NGX_OK) {
        if (val->not_found == 0) {
            ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "Date: %s", val->data);
            el_sign = ngx_array_push(to_sign);
            if (el_sign == NULL) {
                return NGX_ERROR;
            }
            el_sign->data = val->data;
            el_sign->len  = val->len;
            lenall += el_sign->len;
        }
    }

    ngx_http_aws_auth_sgn_newline(to_sign);

    el_sign = ngx_array_push(to_sign);
    if (el_sign == NULL) {
        return NGX_ERROR;
    }
    ngx_http_aws_auth_get_canon_headers(r, el_sign);
    lenall += el_sign->len;
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "normalized: %V", el_sign);

    el_sign = ngx_array_push(to_sign);
    if (el_sign == NULL) {
        return NGX_ERROR;
    }
    ngx_http_aws_auth_get_canon_resource(r, el_sign);
    lenall += el_sign->len;
    el = to_sign->elts;

    lenall += 4; //newlines 
    u_char * str_to_sign = ngx_palloc(r->pool, lenall + 50);
    int offset = 0;
    for (i = 0; i < to_sign->nelts ; i++) {
        ngx_memcpy(str_to_sign + offset, el[i].data, el[i].len);
        offset += el[i].len;
    }
    *(str_to_sign+offset) = '\0';

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,"String to sign:%s",str_to_sign);


    if (evp_md==NULL)
    {
       evp_md = EVP_sha1();
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "aws string being signed BEGIN:\n%s\naws string being signed END", str_to_sign);

    HMAC(evp_md, aws_conf->secret.data, aws_conf->secret.len, str_to_sign, ngx_strlen(str_to_sign), md, &md_len);

    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bmem = BIO_new(BIO_s_mem());  
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, md, md_len);
    (void)BIO_flush(b64);
    BUF_MEM *bptr; 
    BIO_get_mem_ptr(b64, &bptr);

    ngx_memcpy(str_to_sign, bptr->data, bptr->length-1);
    str_to_sign[bptr->length-1]='\0';

    BIO_free_all(b64);

    u_char *signature = ngx_palloc(r->pool,100 + aws_conf->access_key.len);
    ngx_sprintf(signature, "AWS %V:%s%Z", &aws_conf->access_key, str_to_sign);
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,"Signature: %s",signature);

    v->len = ngx_strlen(signature);
    v->data = signature;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}

static ngx_int_t
ngx_http_aws_auth_variable_date(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{   
    v->len = ngx_cached_http_time.len;
    v->data = ngx_cached_http_time.data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}

static ngx_http_variable_t  ngx_http_aws_auth_vars[] = {
    { ngx_string(AWS_S3_VARIABLE), NULL,
      ngx_http_aws_auth_variable_s3, 0, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string(AWS_DATE_VARIABLE), NULL,
      ngx_http_aws_auth_variable_date, 0, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};

static ngx_int_t
register_variable(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_aws_auth_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;    
}

/* 
 * vim: ts=4 sw=4 et
 */

