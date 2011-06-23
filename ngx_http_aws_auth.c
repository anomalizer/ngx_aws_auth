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

typedef struct {
    ngx_str_t access_key;
    ngx_str_t secret;
    ngx_str_t s3_bucket;
    ngx_str_t chop_prefix;
} ngx_http_aws_auth_conf_t;


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
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_aws_auth_conf_t, s3_bucket),
      NULL },
    
   { ngx_string("chop_prefix"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
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

static ngx_int_t
ngx_http_aws_auth_variable_s3(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_http_aws_auth_conf_t *aws_conf;
    int t;
    unsigned int md_len;
    unsigned char md[EVP_MAX_MD_SIZE];
    aws_conf = ngx_http_get_module_loc_conf(r, ngx_http_aws_auth_module);
    

    /* 
     *   This Block of code added to deal with paths that are not on the root -
     *   that is, via proxy_pass that are being redirected and the base part of 
     *   the proxy url needs to be taken off the beginning of the URI in order 
     *   to sign it correctly.
    */
    u_char *uri = ngx_palloc(r->pool, r->uri.len + 200); // allow room for escaping
    u_char *uri_end = (u_char*) ngx_escape_uri(uri,r->uri.data, r->uri.len, NGX_ESCAPE_URI);
    *uri_end = '\0'; // null terminate

    if(ngx_strcmp(aws_conf->chop_prefix.data, "")) {
	if(!ngx_strncmp(r->uri.data, aws_conf->chop_prefix.data, aws_conf->chop_prefix.len)) {
	  uri += aws_conf->chop_prefix.len;
          ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
            "chop_prefix '%V' chopped from URI",&aws_conf->chop_prefix);
        } else {
          ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "chop_prefix '%V' NOT in URI",&aws_conf->chop_prefix);
        }
    }

    u_char *str_to_sign = ngx_palloc(r->pool,r->uri.len + aws_conf->s3_bucket.len + 200);
    ngx_sprintf(str_to_sign, "GET\n\n\n\nx-amz-date:%V\n/%V%s%Z",
        &ngx_cached_http_time, &aws_conf->s3_bucket,uri);
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,"String to sign:%s",str_to_sign);



    if (evp_md==NULL)
    {
       evp_md = EVP_sha1();
    }

    HMAC(evp_md, aws_conf->secret.data, aws_conf->secret.len, str_to_sign, ngx_strlen(str_to_sign), md, &md_len);

    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bmem = BIO_new(BIO_s_mem());  
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, md, md_len);
    t = BIO_flush(b64); /* read the value esle some gcc, throws error*/
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
