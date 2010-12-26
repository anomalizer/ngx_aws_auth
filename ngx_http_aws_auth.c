#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define AWS_S3_VARIABLE "s3_auth_token"

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
    register_variable,                                  /* preconfiguration */
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
    v->len = 4;
    v->data = ngx_palloc(r->pool, v->len);
    memcpy(v->data, AWS_S3_VARIABLE, v->len);
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}

static ngx_int_t
register_variable(ngx_conf_t *cf)
{
    static ngx_str_t x = ngx_string(AWS_S3_VARIABLE);

    ngx_http_variable_t      *var;

    var = ngx_http_add_variable(cf, &x, NGX_HTTP_VAR_CHANGEABLE);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_aws_auth_variable_s3;
    var->data = (uintptr_t)NULL;

	return NGX_OK;
}

/* 
 * vim: ts=4 sw=4 et
 */
