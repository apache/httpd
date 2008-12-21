#ifndef _LUA_APR_H_
#define _LUA_APR_H_

int apr_lua_init(lua_State *L, apr_pool_t *p);
apr_table_t* check_apr_table(lua_State* L, int index);
void apl_push_apr_table(lua_State* L, const char *name, apr_table_t *t);

#endif /* !_LUA_APR_H_ */
