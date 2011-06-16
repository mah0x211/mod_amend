/* 
  mod_amend.c
  (C) 2011 Masatoshi Teruya.
  
  COMPILE AND INSTALL:
    $ apxs -cia mod_amend.c

  NOTE: 
    if uses on Mac OS X and image not found 
	error occurred, please try below option:
	  $ apxs -c -Wc,-arch -Wc,ppc -Wc,-arch -Wc,i386 -Wc,-arch -Wc,ppc64 -Wc,-arch -Wc,x86_64 -Wl,-arch -Wl,ppc -Wl,-arch -Wl,i386 -Wl,-arch -Wl,ppc64 -Wl,-arch -Wl,x86_64 -i -a ./mod_amend.c

  CONFIGURATION:
    AmendSkip /skip_from/ /skip_to/
    AmendQuery /query_from/ /query_to/ query_separator
*/ 
#include "httpd.h"
#include "http_log.h"
#include "http_core.h"
#include "http_config.h"
#include "http_request.h"
#include "ap_config.h"
#include "apr.h"
#include "apr_strings.h"

#define PRODUCT_NAME "mod_amend"
#define PRODUCT_VERSION "0.0.3"

// logging

#define LOG_RERROR(r,lv,fmt,...)({\
	ap_log_rerror( APLOG_MARK, lv, 0, r, fmt, ##__VA_ARGS__ ); \
})

#define LOG_SERROR(s,lv,fmt,...)({\
	ap_log_error( APLOG_MARK, lv, 0, s, fmt, ##__VA_ARGS__ ); \
})

#define LOG_APR_STRERROR(ec)({\
	char strbuf[MAX_STRING_LEN]; \
	apr_strerror( ec, strbuf, MAX_STRING_LEN ); \
})

/* MARK: Definition */
typedef struct {
	apr_pool_t *p;
	const char *skip_from;
	const char *skip_to;
	const char *skip_rep;
	const char *query_from;
	const char *query_to;
	const char *query_sep;
} amend_cfg;

/* global module structure */
module AP_MODULE_DECLARE_DATA amend_module;

static int amender( request_rec *r, amend_cfg *cfg )
{
	int rc = DECLINED;
	
	if( cfg->skip_from || cfg->query_from )
	{
		size_t len = strlen( r->unparsed_uri );
		char *uri = calloc( sizeof( char ), len + 1 );
		
		if( !uri ){
			LOG_RERROR( r, APLOG_ERR, "mod_amend: %s", strerror( errno ) );
			rc = HTTP_INTERNAL_SERVER_ERROR;
		}
		else
		{
			char *qry = NULL;
			char *head = NULL;
			char *tail = NULL;
			int rv = OK;

			memcpy( uri, r->unparsed_uri, len );
			
			if( cfg->skip_from )
			{
				if( strcmp( cfg->skip_from, "^" ) == 0 ){
					head = uri;
				}
				else if( !( head = strstr( uri, cfg->skip_from ) ) ){
					rv = HTTP_NOT_FOUND;
				}
				if( rv != HTTP_NOT_FOUND && 
					( tail = strstr( head, cfg->skip_to ) ) && 
					strcmp( head, tail ) != 0 )
				{
					if( cfg->skip_rep && *cfg->skip_rep )
					{
						size_t rlen = strlen( cfg->skip_rep );
						size_t tlen = strlen( cfg->skip_to );
						size_t shift = rlen - tlen;
						
						if( shift > 0 && !( uri = realloc( uri, len + shift ) ) ){
							LOG_RERROR( r, APLOG_ERR, "mod_amend: %s", strerror( errno ) );
							rc = HTTP_INTERNAL_SERVER_ERROR;
						}
						else{
							tail += tlen;
							memmove( (void*)head + rlen, tail, strlen( tail ) + 1 );
							memcpy( (void*)head, cfg->skip_rep, rlen );
							rc = OK;
						}
					}
					else {
						memmove( (void*)head, tail, strlen( tail ) + 1 );
						rc = OK;
					}
				}
			}
			
			if( rc != HTTP_INTERNAL_SERVER_ERROR && 
				cfg->query_from && 
				( head = strstr( uri, cfg->query_from ) ) )
			{
				tail = NULL;
				if( strcmp( cfg->query_to, "$" ) != 0 && 
					!( tail = strstr( head, cfg->query_to ) ) ){
					rv = HTTP_NOT_FOUND;
				}
				
				if( rv != HTTP_NOT_FOUND )
				{
					size_t qlen = strlen( head );
					
					len = ( tail ) ? strlen( tail ) : 0;
					qlen -= len;
					if( !( qry = calloc( sizeof( char ), qlen ) ) ){
						LOG_RERROR( r, APLOG_ERR, "mod_amend: %s", strerror( errno ) );
						rc = HTTP_INTERNAL_SERVER_ERROR;
					}
					else
					{
						rc = OK;
						memcpy( qry, head + strlen( cfg->query_from ), qlen );
						if( tail ){
							memmove( head, tail, len + 1 );
						}
						else {
							*head = '/';
							head[1] = 0;
						}
						
						head = qry;
						len = strlen( cfg->query_sep );
						while( ( head = strstr( head, cfg->query_sep ) ) ){
							memmove( head + 1, head + len, strlen( head ) - len );
							*head = '&';
							head++;
						}
					}
				}
			}
			
			if( rc == OK )
			{
				apr_table_set( r->headers_out, "X-Amend-URI", r->unparsed_uri );
				if( qry ){
					r->unparsed_uri = apr_pstrcat( r->pool, uri, "?", qry, NULL );
					r->args = apr_pstrdup( r->pool, qry );
					r->parsed_uri.query = apr_pstrdup( r->pool, qry );
					free( qry );
				}
				else {
					r->unparsed_uri = apr_pstrdup( r->pool, uri );
				}
				r->uri = apr_pstrdup( r->pool, uri );
				r->parsed_uri.path = apr_pstrdup( r->pool, uri );
				r->path_info = "";
				r->filename = NULL;
				r->canonical_filename = NULL;
				free( uri );
			}
		}
	}
	
	return rc;
}

static int translate_name( request_rec *r )
{
	int rc = DECLINED;
	amend_cfg *cfg = NULL;
	
	if( !r->main && !r->prev )
	{
		if( ( cfg = ap_get_module_config( r->server->module_config , &amend_module ) ) &&
			( rc = amender( r, cfg ) ) != HTTP_INTERNAL_SERVER_ERROR ){
			rc = DECLINED;
		}
	}
	
	return rc;
}

static int post_config( apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s )
{
	apr_status_t rc;
	void *tmp = NULL;
	
	if( ( rc = apr_pool_userdata_get( &tmp, PRODUCT_NAME, s->process->pool ) ) ){
		LOG_SERROR( s, APLOG_ERR, "failed to apr_pool_userdata_get(): %s", LOG_APR_STRERROR( rc ) );
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	else if( !tmp )
	{
		if( ( rc = apr_pool_userdata_set( (void*)1, PRODUCT_NAME, NULL, s->process->pool ) ) ){
			LOG_SERROR( s, APLOG_ERR, "failed to apr_pool_userdata_set(): %s", LOG_APR_STRERROR( rc ) );
			return HTTP_INTERNAL_SERVER_ERROR;
		}
	}
	else{
		ap_add_version_component( pconf, PRODUCT_NAME "/" PRODUCT_VERSION );
	}
	
	return rc;
}

static void register_hooks( apr_pool_t *p )
{
	static const char * const asz[]={ "mod_rewrite.c", "mod_proxy.c", NULL };
	ap_hook_post_config( post_config, NULL, NULL, APR_HOOK_MIDDLE );
	ap_hook_translate_name( translate_name, NULL, asz, APR_HOOK_FIRST );
}

/* MARK: Configuration */
static void *create_server_config( apr_pool_t *p, server_rec *server )
{
	amend_cfg *cfg = NULL;
	apr_status_t rc = APR_SUCCESS;
	apr_pool_t *sp = NULL;
	
	// create sub-pool
	if( ( rc = apr_pool_create( &sp, p ) ) ){
		LOG_SERROR( server, APLOG_ERR, "failed to apr_pool_create(): %s", LOG_APR_STRERROR( rc ) );
	}
	// allocate amend_cfg
	else if( !( cfg = apr_pcalloc( sp, sizeof( amend_cfg ) ) ) ){
		LOG_SERROR( server, APLOG_ERR, "failed to apr_pcalloc(): %s", LOG_APR_STRERROR( APR_ENOMEM ) );
		apr_pool_destroy( sp );
	}
	else{
		cfg->p = sp;
		cfg->skip_from = NULL;
		cfg->skip_to = NULL;
		cfg->skip_rep = NULL;
		cfg->query_from = NULL;
		cfg->query_to = NULL;
		cfg->query_sep = NULL;
	}
	
	return cfg;
}

static void *merge_server_config( apr_pool_t *p, void *parent_conf, void *newloc_conf )
{
	amend_cfg *merged = (amend_cfg*)apr_pcalloc( p, sizeof( amend_cfg ) );
	amend_cfg *parent = (amend_cfg*)parent_conf;
	amend_cfg *child = (amend_cfg*)newloc_conf;
	
	merged->p = p;
	merged->skip_from = ( child->skip_from ) ? child->skip_from : parent->skip_from;
	merged->skip_to = ( child->skip_to ) ? child->skip_to : parent->skip_to;
	merged->skip_rep = ( child->skip_rep ) ? child->skip_rep : parent->skip_rep;
	merged->query_from = ( child->query_from ) ? child->query_from : parent->query_from;
	merged->query_to = ( child->query_to ) ? child->query_to : parent->query_to;
	merged->query_sep = ( child->query_sep ) ? child->query_sep : parent->query_sep;
	
	return (void*)merged;
}


/* MARK: Command Directive */
static const char *cmd_set_amend_skip( cmd_parms *cmd, void *mconfig, const char *from, const char *to, const char *rep )
{
	amend_cfg *cfg = ap_get_module_config( cmd->server->module_config , &amend_module );
	
	if( cfg ){
		cfg->skip_from = from;
		cfg->skip_to = to;
		cfg->skip_rep = rep;
	}
	
	return NULL;
}

static const char *cmd_set_amend_query( cmd_parms *cmd, void *mconfig, const char *from, const char *to, const char *sep )
{
	amend_cfg *cfg = ap_get_module_config( cmd->server->module_config , &amend_module );
	
	if( cfg ){
		cfg->query_from = from;
		cfg->query_to = to;
		cfg->query_sep = sep;
	}
	
	return NULL;
}

static const command_rec cmd_table[] =
{
	AP_INIT_TAKE23(
		"AmendSkip",
		cmd_set_amend_skip,
		NULL,
		RSRC_CONF,
		""
	),
	AP_INIT_TAKE3(
		"AmendQuery",
		cmd_set_amend_query,
		NULL,
		RSRC_CONF,
		""
	),
	{NULL}
};

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA amend_module = {
    STANDARD20_MODULE_STUFF, 
    NULL,					/* create per-dir    config structures */
    NULL,					/* merge  per-dir    config structures */
    create_server_config,	/* create per-server config structures */
    merge_server_config,	/* merge  per-server config structures */
    cmd_table,				/* table of config file commands       */
    register_hooks			/* register hooks                      */
};

