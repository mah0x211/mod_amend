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
#include "ap_config.h"
#include "apr.h"
#include "apr_strings.h"

#define PRODUCT_NAME "mod_amend"
#define PRODUCT_VERSION "0.0.1"

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
	const char *query_from;
	const char *query_to;
	const char *query_sep;
} dir_cfg;

/* global module structure */
module AP_MODULE_DECLARE_DATA amend_module;

static int translate_name( request_rec *r )
{
	int rc = DECLINED;
	dir_cfg *cfg = NULL;
	
	if( !r->main && !r->prev && ( cfg = ap_get_module_config( r->per_dir_config , &amend_module ) ) )
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
			int rv;
			
			memcpy( uri, r->unparsed_uri, len );
			
			if( cfg->skip_from )
			{
				if( strcmp( cfg->skip_from, "^" ) == 0 ){
					head = uri;
				}
				else if( !( head = strstr( uri, cfg->skip_from ) ) ){
					rc = HTTP_NOT_FOUND;
				}
				
				if( rc == HTTP_NOT_FOUND || !( tail = strstr( head, cfg->skip_to ) ) ){
					rc = DECLINED;
				}
				else {
					len = strlen( tail );
					memmove( (void*)head, tail, len + 1 );
				}
			}

			if( cfg->query_from && ( head = strstr( uri, cfg->query_from ) ) )
			{
				tail = NULL;
				if( strcmp( cfg->query_to, "$" ) != 0 && 
					!( tail = strstr( head, cfg->query_to ) ) ){
					rc = HTTP_NOT_FOUND;
				}
				
				if( rc == HTTP_NOT_FOUND ){
					rc = DECLINED;
				}
				else
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
			
			if( rc == DECLINED )
			{
				r->uri = apr_pstrdup( r->pool, uri );
				if( qry ){
					r->unparsed_uri = apr_pstrcat( r->pool, uri, "?", qry, NULL );
					free( qry );
				}
				else {
					r->unparsed_uri = apr_pstrdup( r->pool, uri );
				}
				free( uri );
				ap_parse_uri( r, r->unparsed_uri );
			}
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
static void *create_dir_config( apr_pool_t *p, char *dir )
{
	apr_status_t rc;
	dir_cfg *cfg = NULL;
	apr_pool_t *sp = NULL;
	
	if( ( rc = apr_pool_create( &sp, p ) ) ){
		ap_log_perror( APLOG_MARK, APLOG_ERR, 0, p, "failed to apr_pool_create(): %s", LOG_APR_STRERROR( rc ) );
	}
	else if( !( cfg = apr_pcalloc( sp, sizeof( dir_cfg ) ) ) ){
		ap_log_perror( APLOG_MARK, APLOG_ERR, 0, p, "failed to apr_pcalloc(): %s", LOG_APR_STRERROR( APR_ENOMEM ) );
		apr_pool_destroy( sp );
		cfg = NULL;
	}
	else {
		cfg->p = sp;
		cfg->skip_from = NULL;
		cfg->skip_to = NULL;
		cfg->query_from = NULL;
		cfg->query_to = NULL;
		cfg->query_sep = NULL;
	}
	
	return cfg;
}

static void *merge_dir_config( apr_pool_t *p, void *parent_conf, void *newloc_conf )
{
	dir_cfg *merged = (dir_cfg*)apr_pcalloc( p, sizeof( dir_cfg ) );
	dir_cfg *parent = (dir_cfg*)parent_conf;
	dir_cfg *child = (dir_cfg*)newloc_conf;
	
	merged->p = p;
	merged->skip_from = ( child->skip_from ) ? child->skip_from : parent->skip_from;
	merged->skip_to = ( child->skip_to ) ? child->skip_to : parent->skip_to;
	merged->query_from = ( child->query_from ) ? child->query_from : parent->query_from;
	merged->query_to = ( child->query_to ) ? child->query_to : parent->query_to;
	merged->query_sep = ( child->query_sep ) ? child->query_sep : parent->query_sep;
	
	return (void*)merged;
}


/* MARK: Command Directive */
static const char *cmd_set_amend_skip( cmd_parms *cmd, void *mconfig, const char *from, const char *to )
{
	dir_cfg *cfg = (dir_cfg*)mconfig;
	const char *errstr = NULL;
	
	if( cfg ){
		cfg->skip_from = from;
		cfg->skip_to = to;
	}
	
	return errstr;
}

static const char *cmd_set_amend_query( cmd_parms *cmd, void *mconfig, const char *from, const char *to, const char *sep )
{
	dir_cfg *cfg = (dir_cfg*)mconfig;
	const char *errstr = NULL;
	
	if( cfg ){
		cfg->query_from = from;
		cfg->query_to = to;
		cfg->query_sep = sep;
	}
	
	return errstr;
}

static const command_rec cmd_table[] =
{
	AP_INIT_TAKE2(
		"AmendSkip",
		cmd_set_amend_skip,
		NULL,
		OR_FILEINFO,
		""
	),
	AP_INIT_TAKE3(
		"AmendQuery",
		cmd_set_amend_query,
		NULL,
		OR_FILEINFO,
		""
	),
	{NULL}
};

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA amend_module = {
    STANDARD20_MODULE_STUFF, 
    create_dir_config,  /* create per-dir    config structures */
    merge_dir_config,   /* merge  per-dir    config structures */
    NULL,               /* create per-server config structures */
    NULL,               /* merge  per-server config structures */
    cmd_table,          /* table of config file commands       */
    register_hooks      /* register hooks                      */
};


/* MARK: Utilities 
static void ShowProps( request_rec *r )
{
	LOG_RERROR( r, APLOG_ERR, "       the_request: %s", r->the_request );
	LOG_RERROR( r, APLOG_ERR, "      assbackwords: %d", r->assbackwards );
	LOG_RERROR( r, APLOG_ERR, "          proxyreq: %d", r->proxyreq );
	LOG_RERROR( r, APLOG_ERR, "       header_only: %d", r->header_only );
	LOG_RERROR( r, APLOG_ERR, "          protocol: %s", r->protocol );
	LOG_RERROR( r, APLOG_ERR, "         proto_num: %d", r->proto_num );
	LOG_RERROR( r, APLOG_ERR, "          hostname: %s", r->hostname );
	LOG_RERROR( r, APLOG_ERR, "      request_time: %lld", r->request_time );
	LOG_RERROR( r, APLOG_ERR, "       status_line: %s", r->status_line );
	LOG_RERROR( r, APLOG_ERR, "            status: %d", r->status );
	LOG_RERROR( r, APLOG_ERR, "            method: %s", r->method );
	LOG_RERROR( r, APLOG_ERR, "     method_number: %d", r->method_number );
	LOG_RERROR( r, APLOG_ERR, "           allowed: %ld", r->allowed );
	LOG_RERROR( r, APLOG_ERR, "       sent_bodyct: %lu", r->sent_bodyct );
	LOG_RERROR( r, APLOG_ERR, "        bytes_sent: %lu", r->bytes_sent );
	LOG_RERROR( r, APLOG_ERR, "             mtime: %lld", r->mtime );
	LOG_RERROR( r, APLOG_ERR, "           chunked: %d", r->chunked );
	LOG_RERROR( r, APLOG_ERR, "             range: %s", r->range );
	LOG_RERROR( r, APLOG_ERR, "           clength: %ld", r->clength );
	LOG_RERROR( r, APLOG_ERR, "         remaining: %ld", r->remaining );
	LOG_RERROR( r, APLOG_ERR, "       read_length: %ld", r->read_length );
	LOG_RERROR( r, APLOG_ERR, "         read_body: %d", r->read_body );
	LOG_RERROR( r, APLOG_ERR, "      read_chunked: %d", r->read_chunked );
	LOG_RERROR( r, APLOG_ERR, "     expecting_100: %u", r->expecting_100 );
	LOG_RERROR( r, APLOG_ERR, "      content_type: %s", r->content_type );
	LOG_RERROR( r, APLOG_ERR, "           handler: %s", r->handler );
	LOG_RERROR( r, APLOG_ERR, "  content_encoding: %s", r->content_encoding );
	LOG_RERROR( r, APLOG_ERR, "   vlist_validator: %s", r->vlist_validator );
	LOG_RERROR( r, APLOG_ERR, "              user: %s", r->user );
	LOG_RERROR( r, APLOG_ERR, "      ap_auth_type: %s", r->ap_auth_type );
	LOG_RERROR( r, APLOG_ERR, "          no_cache: %d", r->no_cache );
	LOG_RERROR( r, APLOG_ERR, "     no_local_copy: %d", r->no_local_copy );
	LOG_RERROR( r, APLOG_ERR, "      unparsed_uri: %s", r->unparsed_uri );
	LOG_RERROR( r, APLOG_ERR, "               uri: %s", r->uri );
	LOG_RERROR( r, APLOG_ERR, "          filename: %s", r->filename );
	LOG_RERROR( r, APLOG_ERR, "canonical_filename: %s", r->canonical_filename );
	LOG_RERROR( r, APLOG_ERR, "         path_info: %s", r->path_info );
	LOG_RERROR( r, APLOG_ERR, "              args: %s", r->args );
	LOG_RERROR( r, APLOG_ERR, "    used_path_info: %d", r->used_path_info );
	LOG_RERROR( r, APLOG_ERR, "          eos_sent: %d", r->eos_sent );
	LOG_RERROR( r, APLOG_ERR, "      ap_auth_type: %s", ap_auth_type(r) );

	LOG_RERROR( r, APLOG_ERR, "             finfo ->" );
	LOG_RERROR( r, APLOG_ERR, "                 valid: %d", r->finfo.valid );
	LOG_RERROR( r, APLOG_ERR, "            protection: %d", r->finfo.protection );
	LOG_RERROR( r, APLOG_ERR, "              filetype: %d", r->finfo.filetype );
	LOG_RERROR( r, APLOG_ERR, "                  user: %d", r->finfo.user );
	LOG_RERROR( r, APLOG_ERR, "                 group: %d", r->finfo.group );
	LOG_RERROR( r, APLOG_ERR, "                 inode: %d", r->finfo.inode );
	LOG_RERROR( r, APLOG_ERR, "                device: %u", r->finfo.device );
	LOG_RERROR( r, APLOG_ERR, "                 nlink: %d", r->finfo.nlink );
	LOG_RERROR( r, APLOG_ERR, "                  size: %lu", r->finfo.size );
	LOG_RERROR( r, APLOG_ERR, "                 csize: %lu", r->finfo.csize );
	LOG_RERROR( r, APLOG_ERR, "                 atime: %lu", r->finfo.atime );
	LOG_RERROR( r, APLOG_ERR, "                 mtime: %lu", r->finfo.mtime );
	LOG_RERROR( r, APLOG_ERR, "                 ctime: %lu", r->finfo.ctime );
	LOG_RERROR( r, APLOG_ERR, "                 fname: %s", r->finfo.fname );
	LOG_RERROR( r, APLOG_ERR, "                  name: %s", r->finfo.name );
	LOG_RERROR( r, APLOG_ERR, "              filehand: %p", r->finfo.filehand );
	
	LOG_RERROR( r, APLOG_ERR, "        parsed_uri ->" );
	LOG_RERROR( r, APLOG_ERR, "                scheme: %s", r->parsed_uri.scheme );
	LOG_RERROR( r, APLOG_ERR, "              hostinfo: %s", r->parsed_uri.hostinfo );
	LOG_RERROR( r, APLOG_ERR, "                  user: %s", r->parsed_uri.user );
	LOG_RERROR( r, APLOG_ERR, "              password: %s", r->parsed_uri.password );
	LOG_RERROR( r, APLOG_ERR, "              hostname: %s", r->parsed_uri.hostname );
	LOG_RERROR( r, APLOG_ERR, "              port_str: %s", r->parsed_uri.port_str );
	LOG_RERROR( r, APLOG_ERR, "                  path: %s", r->parsed_uri.path );
	LOG_RERROR( r, APLOG_ERR, "                 query: %s", r->parsed_uri.query );
	LOG_RERROR( r, APLOG_ERR, "              fragment: %s", r->parsed_uri.fragment );
	// LOG_RERROR( r, APLOG_ERR, "            hostent: %s", r->parsed_uri.filehand );
	LOG_RERROR( r, APLOG_ERR, "                  port: %d", r->parsed_uri.port );
	LOG_RERROR( r, APLOG_ERR, "        is_initialized: %u", r->parsed_uri.is_initialized );
	LOG_RERROR( r, APLOG_ERR, "         dns_looked_up: %u", r->parsed_uri.dns_looked_up );
	LOG_RERROR( r, APLOG_ERR, "          dns_resolved: %u", r->parsed_uri.dns_resolved );
}
*/
