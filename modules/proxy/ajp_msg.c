/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "ajp.h"


static char *hex_table = "0123456789ABCDEF";

/**
 * Dump up to the first 1024 bytes on an AJP Message
 *
 * @param pool      pool to allocate from
 * @param msg       AJP Message to dump
 * @param err       error string to display
 * @return          dump message
 */
char * ajp_msg_dump(apr_pool_t *pool, ajp_msg_t *msg, char *err)
{
    apr_size_t  i, j;
    char        line[80];
    char        *current;
    char        *rv, *p;
    apr_size_t  bl = 8192;
    apr_byte_t  x;
    apr_size_t  len = msg->len;

    /* Display only first 1024 bytes */
    if (len > 1024)
        len = 1024;
    rv = apr_palloc(pool, bl);
    apr_snprintf(rv, bl,
                 "ajp_msg_dump(): %s pos=%" APR_SIZE_T_FMT
                 " len=%" APR_SIZE_T_FMT " max=%" APR_SIZE_T_FMT "\n",
                 err, msg->pos, msg->len, msg->max_size);
    bl -= strlen(rv);
    p = rv + strlen(rv);
    for (i = 0; i < len; i += 16) {
        current = line;

        for (j = 0; j < 16; j++) {
             x = msg->buf[i + j];

            *current++ = hex_table[x >> 4];
            *current++ = hex_table[x & 0x0f];
            *current++ = ' ';
        }
        *current++ = ' ';
        *current++ = '-';
        *current++ = ' ';
        for (j = 0; j < 16; j++) {
            x = msg->buf[i + j];

            if (x > 0x20 && x < 0x7F) {
                *current++ = x;
            }
            else {
                *current++ = '.';
            }
        }

        *current++ = '\0';
        apr_snprintf(p, bl,
                     "ajp_msg_dump(): %.4lx    %s\n",
                     (unsigned long)i, line);
        bl -= strlen(rv);
        p = rv + strlen(rv);

    }

    return rv;
}


/**
 * Check a new AJP Message by looking at signature and return its size
 *
 * @param msg       AJP Message to check
 * @param len       Pointer to returned len
 * @return          APR_SUCCESS or error
 */
apr_status_t ajp_msg_check_header(ajp_msg_t *msg, apr_size_t *len)
{
    apr_byte_t *head = msg->buf;
    apr_size_t msglen;

    if (!((head[0] == 0x41 && head[1] == 0x42) ||
          (head[0] == 0x12 && head[1] == 0x34))) {

        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                      "ajp_check_msg_header() got bad signature %x%x",
                      head[0], head[1]);

        return AJP_EBAD_SIGNATURE;
    }

    msglen  = ((head[2] & 0xff) << 8);
    msglen += (head[3] & 0xFF);

    if (msglen > msg->max_size) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                     "ajp_check_msg_header() incoming message is "
                     "too big %" APR_SIZE_T_FMT ", max is %" APR_SIZE_T_FMT,
                     msglen, msg->max_size);
        return AJP_ETOBIG;
    }

    msg->len = msglen + AJP_HEADER_LEN;
    msg->pos = AJP_HEADER_LEN;
    *len     = msglen;

    return APR_SUCCESS;
}

/**
 * Reset an AJP Message
 *
 * @param msg       AJP Message to reset
 * @return          APR_SUCCESS or error
 */
apr_status_t ajp_msg_reset(ajp_msg_t *msg)
{
    msg->len = AJP_HEADER_LEN;
    msg->pos = AJP_HEADER_LEN;

    return APR_SUCCESS;
}

/**
 * Reuse an AJP Message
 *
 * @param msg       AJP Message to reuse
 * @return          APR_SUCCESS or error
 */
apr_status_t ajp_msg_reuse(ajp_msg_t *msg)
{
    apr_byte_t *buf;
    apr_size_t max_size;

    buf = msg->buf;
    max_size = msg->max_size;
    memset(msg, 0, sizeof(ajp_msg_t));
    msg->buf = buf;
    msg->max_size = max_size;
    msg->header_len = AJP_HEADER_LEN;
    ajp_msg_reset(msg);
    return APR_SUCCESS;
}

/**
 * Mark the end of an AJP Message
 *
 * @param msg       AJP Message to end
 * @return          APR_SUCCESS or error
 */
apr_status_t ajp_msg_end(ajp_msg_t *msg)
{
    apr_size_t len = msg->len - AJP_HEADER_LEN;

    if (msg->server_side) {
        msg->buf[0] = 0x41;
        msg->buf[1] = 0x42;
    }
    else {
        msg->buf[0] = 0x12;
        msg->buf[1] = 0x34;
    }

    msg->buf[2] = (apr_byte_t)((len >> 8) & 0xFF);
    msg->buf[3] = (apr_byte_t)(len & 0xFF);

    return APR_SUCCESS;
}

static APR_INLINE int ajp_log_overflow(ajp_msg_t *msg, const char *context)
{
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                 "%s(): BufferOverflowException %" APR_SIZE_T_FMT
                 " %" APR_SIZE_T_FMT,
                 context, msg->pos, msg->len);
    return AJP_EOVERFLOW;
}

/**
 * Add an unsigned 32bits value to AJP Message
 *
 * @param msg       AJP Message to get value from
 * @param value     value to add to AJP Message
 * @return          APR_SUCCESS or error
 */
apr_status_t ajp_msg_append_uint32(ajp_msg_t *msg, apr_uint32_t value)
{
    apr_size_t len = msg->len;

    if ((len + 4) > msg->max_size) {
        return ajp_log_overflow(msg, "ajp_msg_append_uint32");
    }

    msg->buf[len]     = (apr_byte_t)((value >> 24) & 0xFF);
    msg->buf[len + 1] = (apr_byte_t)((value >> 16) & 0xFF);
    msg->buf[len + 2] = (apr_byte_t)((value >> 8) & 0xFF);
    msg->buf[len + 3] = (apr_byte_t)(value & 0xFF);

    msg->len += 4;

    return APR_SUCCESS;
}

/**
 * Add an unsigned 16bits value to AJP Message
 *
 * @param msg       AJP Message to get value from
 * @param value     value to add to AJP Message
 * @return          APR_SUCCESS or error
 */
apr_status_t ajp_msg_append_uint16(ajp_msg_t *msg, apr_uint16_t value)
{
    apr_size_t len = msg->len;

    if ((len + 2) > msg->max_size) {
        return ajp_log_overflow(msg, "ajp_msg_append_uint16");
    }

    msg->buf[len]     = (apr_byte_t)((value >> 8) & 0xFF);
    msg->buf[len + 1] = (apr_byte_t)(value & 0xFF);

    msg->len += 2;

    return APR_SUCCESS;
}

/**
 * Add an unsigned 8bits value to AJP Message
 *
 * @param msg       AJP Message to get value from
 * @param value     value to add to AJP Message
 * @return          APR_SUCCESS or error
 */
apr_status_t ajp_msg_append_uint8(ajp_msg_t *msg, apr_byte_t value)
{
    apr_size_t len = msg->len;

    if ((len + 1) > msg->max_size) {
        return ajp_log_overflow(msg, "ajp_msg_append_uint8");
    }

    msg->buf[len] = value;
    msg->len += 1;

    return APR_SUCCESS;
}

/**
 *  Add a String in AJP message, and transform the String in ASCII
 *  if convert is set and we're on an EBCDIC machine
 *
 * @param msg       AJP Message to get value from
 * @param value     Pointer to String
 * @param convert   When set told to convert String to ASCII
 * @return          APR_SUCCESS or error
 */
apr_status_t ajp_msg_append_string_ex(ajp_msg_t *msg, const char *value,
                                      int convert)
{
    apr_size_t len;

    if (value == NULL) {
        return(ajp_msg_append_uint16(msg, 0xFFFF));
    }

    len = strlen(value);
    if ((msg->len + len + 2) > msg->max_size) {
        return ajp_log_overflow(msg, "ajp_msg_append_cvt_string");
    }

    /* ignore error - we checked once */
    ajp_msg_append_uint16(msg, (apr_uint16_t)len);

    /* We checked for space !!  */
    memcpy(msg->buf + msg->len, value, len + 1); /* including \0 */

    if (convert)   /* convert from EBCDIC if needed */
        ajp_xlate_to_ascii((char *)msg->buf + msg->len, len + 1);

    msg->len += len + 1;

    return APR_SUCCESS;
}

/**
 * Add a Byte array to AJP Message
 *
 * @param msg       AJP Message to get value from
 * @param value     Pointer to Byte array
 * @param valuelen  Byte array len
 * @return          APR_SUCCESS or error
 */
apr_status_t ajp_msg_append_bytes(ajp_msg_t *msg, const apr_byte_t *value,
                                  apr_size_t valuelen)
{
    if (! valuelen) {
        return APR_SUCCESS; /* Shouldn't we indicate an error ? */
    }

    if ((msg->len + valuelen) > msg->max_size) {
        return ajp_log_overflow(msg, "ajp_msg_append_bytes");
    }

    /* We checked for space !!  */
    memcpy(msg->buf + msg->len, value, valuelen);
    msg->len += valuelen;

    return APR_SUCCESS;
}

/**
 * Get a 32bits unsigned value from AJP Message
 *
 * @param msg       AJP Message to get value from
 * @param rvalue    Pointer where value will be returned
 * @return          APR_SUCCESS or error
 */
apr_status_t ajp_msg_get_uint32(ajp_msg_t *msg, apr_uint32_t *rvalue)
{
    apr_uint32_t value;

    if ((msg->pos + 3) > msg->len) {
        return ajp_log_overflow(msg, "ajp_msg_get_uint32");
    }

    value  = ((msg->buf[(msg->pos++)] & 0xFF) << 24);
    value |= ((msg->buf[(msg->pos++)] & 0xFF) << 16);
    value |= ((msg->buf[(msg->pos++)] & 0xFF) << 8);
    value |= ((msg->buf[(msg->pos++)] & 0xFF));

    *rvalue = value;
    return APR_SUCCESS;
}


/**
 * Get a 16bits unsigned value from AJP Message
 *
 * @param msg       AJP Message to get value from
 * @param rvalue    Pointer where value will be returned
 * @return          APR_SUCCESS or error
 */
apr_status_t ajp_msg_get_uint16(ajp_msg_t *msg, apr_uint16_t *rvalue)
{
    apr_uint16_t value;

    if ((msg->pos + 1) > msg->len) {
        return ajp_log_overflow(msg, "ajp_msg_get_uint16");
    }

    value  = ((msg->buf[(msg->pos++)] & 0xFF) << 8);
    value += ((msg->buf[(msg->pos++)] & 0xFF));

    *rvalue = value;
    return APR_SUCCESS;
}

/**
 * Peek a 16bits unsigned value from AJP Message, position in message
 * is not updated
 *
 * @param msg       AJP Message to get value from
 * @param rvalue    Pointer where value will be returned
 * @return          APR_SUCCESS or error
 */
apr_status_t ajp_msg_peek_uint16(ajp_msg_t *msg, apr_uint16_t *rvalue)
{
    apr_uint16_t value;

    if ((msg->pos + 1) > msg->len) {
        return ajp_log_overflow(msg, "ajp_msg_peek_uint16");
    }

    value = ((msg->buf[(msg->pos)] & 0xFF) << 8);
    value += ((msg->buf[(msg->pos + 1)] & 0xFF));

    *rvalue = value;
    return APR_SUCCESS;
}

/**
 * Peek a 8bits unsigned value from AJP Message, position in message
 * is not updated
 *
 * @param msg       AJP Message to get value from
 * @param rvalue    Pointer where value will be returned
 * @return          APR_SUCCESS or error
 */
apr_status_t ajp_msg_peek_uint8(ajp_msg_t *msg, apr_byte_t *rvalue)
{
    if (msg->pos > msg->len) {
        return ajp_log_overflow(msg, "ajp_msg_peek_uint8");
    }

    *rvalue = msg->buf[msg->pos];
    return APR_SUCCESS;
}

/**
 * Get a 8bits unsigned value from AJP Message
 *
 * @param msg       AJP Message to get value from
 * @param rvalue    Pointer where value will be returned
 * @return          APR_SUCCESS or error
 */
apr_status_t ajp_msg_get_uint8(ajp_msg_t *msg, apr_byte_t *rvalue)
{

    if (msg->pos > msg->len) {
        return ajp_log_overflow(msg, "ajp_msg_get_uint8");
    }

    *rvalue = msg->buf[msg->pos++];
    return APR_SUCCESS;
}


/**
 * Get a String value from AJP Message
 *
 * @param msg       AJP Message to get value from
 * @param rvalue    Pointer where value will be returned
 * @return          APR_SUCCESS or error
 */
apr_status_t ajp_msg_get_string(ajp_msg_t *msg, const char **rvalue)
{
    apr_uint16_t size;
    apr_size_t   start;
    apr_status_t status;

    status = ajp_msg_get_uint16(msg, &size);
    start = msg->pos;

    if ((status != APR_SUCCESS) || (size + start > msg->max_size)) {
        return ajp_log_overflow(msg, "ajp_msg_get_string");
    }

    msg->pos += (apr_size_t)size;
    msg->pos++;                   /* a String in AJP is NULL terminated */

    *rvalue = (const char *)(msg->buf + start);
    return APR_SUCCESS;
}


/**
 * Get a Byte array from AJP Message
 *
 * @param msg       AJP Message to get value from
 * @param rvalue    Pointer where value will be returned
 * @param rvalueLen Pointer where Byte array len will be returned
 * @return          APR_SUCCESS or error
 */
apr_status_t ajp_msg_get_bytes(ajp_msg_t *msg, apr_byte_t **rvalue,
                               apr_size_t *rvalue_len)
{
    apr_uint16_t size;
    apr_size_t   start;
    apr_status_t status;

    status = ajp_msg_get_uint16(msg, &size);
    /* save the current position */
    start = msg->pos;

    if ((status != APR_SUCCESS) || (size + start > msg->max_size)) {
        return ajp_log_overflow(msg, "ajp_msg_get_bytes");
    }
    msg->pos += (apr_size_t)size;   /* only bytes, no trailer */

    *rvalue     = msg->buf + start;
    *rvalue_len = size;

    return APR_SUCCESS;
}


/**
 * Create an AJP Message from pool
 *
 * @param pool      memory pool to allocate AJP message from
 * @param size      size of the buffer to create
 * @param rmsg      Pointer to newly created AJP message
 * @return          APR_SUCCESS or error
 */
apr_status_t ajp_msg_create(apr_pool_t *pool, apr_size_t size, ajp_msg_t **rmsg)
{
    ajp_msg_t *msg = (ajp_msg_t *)apr_pcalloc(pool, sizeof(ajp_msg_t));

    if (!msg) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                      "ajp_msg_create(): can't allocate AJP message memory");
        return APR_ENOPOOL;
    }

    msg->server_side = 0;

    msg->buf = (apr_byte_t *)apr_palloc(pool, size);

    /* XXX: This should never happen
     * In case if the OS cannont allocate 8K of data
     * we are in serious trouble
     * No need to check the alloc return value, cause the
     * core dump is probably the best solution anyhow.
     */
    if (msg->buf == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                      "ajp_msg_create(): can't allocate AJP message memory");
        return APR_ENOPOOL;
    }

    msg->len = 0;
    msg->header_len = AJP_HEADER_LEN;
    msg->max_size = size;
    *rmsg = msg;

    return APR_SUCCESS;
}

/**
 * Recopy an AJP Message to another
 *
 * @param smsg      source AJP message
 * @param dmsg      destination AJP message
 * @return          APR_SUCCESS or error
 */
apr_status_t ajp_msg_copy(ajp_msg_t *smsg, ajp_msg_t *dmsg)
{
    if (dmsg == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                     "ajp_msg_copy(): destination msg is null");
        return AJP_EINVAL;
    }

    if (smsg->len > smsg->max_size) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                     "ajp_msg_copy(): destination buffer too "
                     "small %" APR_SIZE_T_FMT ", max size is %" APR_SIZE_T_FMT,
                     smsg->len, smsg->max_size);
        return  AJP_ETOSMALL;
    }

    memcpy(dmsg->buf, smsg->buf, smsg->len);
    dmsg->len = smsg->len;
    dmsg->pos = smsg->pos;

    return APR_SUCCESS;
}


/**
 * Serialize in an AJP Message a PING command
 *
 * +-----------------------+
 * | PING CMD (1 byte)     |
 * +-----------------------+
 *
 * @param smsg      AJP message to put serialized message
 * @return          APR_SUCCESS or error
 */
apr_status_t ajp_msg_serialize_ping(ajp_msg_t *msg)
{
    apr_status_t rc;
    ajp_msg_reset(msg);

    if ((rc = ajp_msg_append_uint8(msg, CMD_AJP13_PING)) != APR_SUCCESS)
        return rc;

    return APR_SUCCESS;
}

/**
 * Serialize in an AJP Message a CPING command
 *
 * +-----------------------+
 * | CPING CMD (1 byte)    |
 * +-----------------------+
 *
 * @param smsg      AJP message to put serialized message
 * @return          APR_SUCCESS or error
 */
apr_status_t ajp_msg_serialize_cping(ajp_msg_t *msg)
{
    apr_status_t rc;
    ajp_msg_reset(msg);

    if ((rc = ajp_msg_append_uint8(msg, CMD_AJP13_CPING)) != APR_SUCCESS)
        return rc;

    return APR_SUCCESS;
}
