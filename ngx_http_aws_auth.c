#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define AWS_S3_VARIABLE "s3_auth_token"
#define AWS_DATE_VARIABLE "aws_date"

static void* ngx_http_aws_auth_create_loc_conf(ngx_conf_t *cf);
static char* ngx_http_aws_auth_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t register_variable(ngx_conf_t *cf);

typedef struct {
    ngx_str_t access_key;
    ngx_str_t secret;
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

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_aws_auth_variable_s3(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    

    // TODO get the real stuff going
    v->len = ngx_cached_http_time.len;
    // v->data = ngx_palloc(r->pool, v->len);
    //memcpy(v->data, ngx_cached_http_time.data, v->len);
    v->data = ngx_cached_http_time.data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}

static ngx_int_t
ngx_http_aws_auth_variable_date(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    

    // TODO get the real stuff going
    v->len = ngx_cached_http_time.len;
    // v->data = ngx_palloc(r->pool, v->len);
    //memcpy(v->data, ngx_cached_http_time.data, v->len);
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
