extern module AP_MODULE_DECLARE_DATA apreq_module;

struct dir_config {
    const char         *temp_dir;
    apr_uint64_t        read_limit;
    apr_size_t          brigade_limit;
};

/* The "warehouse", stored in r->request_config */
struct apache2_handle {
    apreq_handle_t      handle;
    request_rec        *r;
    apr_table_t        *jar, *args;
    apr_status_t        jar_status, args_status;
    ap_filter_t        *f;
};

/* Tracks the apreq filter state */
struct filter_ctx {
    apr_bucket_brigade *bb;    /* input brigade that's passed to the parser */
    apr_bucket_brigade *bbtmp; /* temporary copy of bb, destined for the spool */
    apr_bucket_brigade *spool; /* copied prefetch data for downstream filters */
    apreq_parser_t     *parser;
    apreq_hook_t       *hook_queue;
    apreq_hook_t       *find_param;
    apr_table_t        *body;
    apr_status_t        body_status;
    apr_status_t        filter_error;
    apr_uint64_t        bytes_read;     /* Total bytes read into this filter. */
    apr_uint64_t        read_limit;     /* Max bytes the filter may show to parser */
    apr_size_t          brigade_limit;
    const char         *temp_dir;
};

apr_status_t apreq_filter_prefetch(ap_filter_t *f, apr_off_t readbytes);
apr_status_t apreq_filter(ap_filter_t *f,
                          apr_bucket_brigade *bb,
                          ap_input_mode_t mode,
                          apr_read_type_e block,
                          apr_off_t readbytes);

void apreq_filter_make_context(ap_filter_t *f);
void apreq_filter_init_context(ap_filter_t *f);

APR_INLINE
static void apreq_filter_relocate(ap_filter_t *f)
{
    request_rec *r = f->r;

    if (f != r->input_filters) {
        ap_filter_t *top = r->input_filters;
        ap_remove_input_filter(f);
        r->input_filters = f;
        f->next = top;
    }
}
