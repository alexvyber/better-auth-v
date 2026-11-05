#ifndef BETTER_AUTH_MONGO_DRIVER_H
#define BETTER_AUTH_MONGO_DRIVER_H
#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
typedef struct ba_mongo ba_mongo;
#ifdef BA_ENABLE_MONGODB
#include <mongoc/mongoc.h>
#include <pthread.h>
struct ba_mongo { mongoc_client_t *client; mongoc_client_session_t *session; int active; };
static pthread_once_t ba_mongo_once = PTHREAD_ONCE_INIT;
static void ba_mongo_initialize(void) { mongoc_init(); atexit(mongoc_cleanup); }
static char *ba_mongo_result(int ok, const bson_t *reply, const bson_error_t *error) {
    bson_t result = BSON_INITIALIZER;
    BSON_APPEND_BOOL(&result, "ok", ok != 0);
    if (reply) {
        BSON_APPEND_DOCUMENT(&result, "reply", reply);
        // Preserve cursor handles across JSON runtimes that parse numbers as doubles.
        bson_iter_t outer, cursor;
        if (bson_iter_init_find(&outer, reply, "cursor") && BSON_ITER_HOLDS_DOCUMENT(&outer)
            && bson_iter_recurse(&outer, &cursor) && bson_iter_find(&cursor, "id")
            && BSON_ITER_HOLDS_INT64(&cursor)) {
            char text[32];
            bson_snprintf(text, sizeof(text), "%" PRId64, bson_iter_int64(&cursor));
            BSON_APPEND_UTF8(&result, "cursorId", text);
        }
    }
    if (!ok && error) {
        BSON_APPEND_INT64(&result, "code", error->code);
        BSON_APPEND_UTF8(&result, "message", error->message);
    }
    char *json = bson_as_relaxed_extended_json(&result, NULL);
    bson_destroy(&result);
    return json;
}
static ba_mongo *ba_mongo_open(const char *uri_string) {
    pthread_once(&ba_mongo_once, ba_mongo_initialize);
    bson_error_t error = {0};
    mongoc_uri_t *uri = mongoc_uri_new_with_error(uri_string, &error);
    if (!uri) return NULL;
    mongoc_client_t *client = mongoc_client_new_from_uri(uri);
    mongoc_uri_destroy(uri);
    if (!client) return NULL;
    mongoc_client_set_error_api(client, 2);
    mongoc_client_set_appname(client, "better-auth-v");
    ba_mongo *handle = calloc(1, sizeof(*handle));
    if (!handle) { mongoc_client_destroy(client); return NULL; }
    handle->client = client;
    return handle;
}
static void ba_mongo_close(ba_mongo *handle) {
    if (!handle) return;
    if (handle->session) mongoc_client_session_destroy(handle->session);
    mongoc_client_destroy(handle->client);
    free(handle);
}
static char *ba_mongo_command(ba_mongo *handle, const char *database, const uint8_t *bytes, size_t length, int mode, int attach_session) {
    bson_error_t error = {0};
    bson_t reply = BSON_INITIALIZER;
    bson_t options = BSON_INITIALIZER;
    bson_t *command = bson_new_from_data(bytes, length);
    if (!command) {
        bson_set_error(&error, MONGOC_ERROR_BSON, MONGOC_ERROR_BSON_INVALID, "Invalid BSON command");
        char *out = ba_mongo_result(0, &reply, &error);
        bson_destroy(&reply); bson_destroy(&options); return out;
    }
    if (attach_session && handle->active && !mongoc_client_session_append(handle->session, &options, &error)) {
        char *out = ba_mongo_result(0, &reply, &error);
        bson_destroy(command); bson_destroy(&reply); bson_destroy(&options); return out;
    }
    bool ok;
    if (mode == 1) ok = mongoc_client_read_command_with_opts(handle->client, database, command, NULL, &options, &reply, &error);
    else if (mode == 2) ok = mongoc_client_write_command_with_opts(handle->client, database, command, &options, &reply, &error);
    else if (mode == 3) ok = mongoc_client_read_write_command_with_opts(handle->client, database, command, NULL, &options, &reply, &error);
    else ok = mongoc_client_command_with_opts(handle->client, database, command, NULL, &options, &reply, &error);
    char *out = ba_mongo_result(ok, &reply, &error);
    bson_destroy(command); bson_destroy(&reply); bson_destroy(&options);
    return out;
}
static char *ba_mongo_transaction(ba_mongo *handle, int action) {
    bson_error_t error = {0};
    bson_t reply = BSON_INITIALIZER;
    bool ok = true;
    if (action == 1) {
        if (!handle->session) handle->session = mongoc_client_start_session(handle->client, NULL, &error);
        ok = handle->session && mongoc_client_session_start_transaction(handle->session, NULL, &error);
        if (ok) handle->active = 1;
    } else if (action == 2) {
        ok = mongoc_client_session_commit_transaction(handle->session, &reply, &error);
        handle->active = mongoc_client_session_in_transaction(handle->session);
    } else if (handle->session && handle->active) {
        ok = mongoc_client_session_abort_transaction(handle->session, &error);
        handle->active = 0;
    }
    char *out = ba_mongo_result(ok, &reply, &error);
    bson_destroy(&reply);
    return out;
}
static void ba_mongo_oid(char *output) { bson_oid_t oid; bson_oid_init(&oid, NULL); bson_oid_to_string(&oid, output); }
static void ba_mongo_free(char *data) { bson_free(data); }
#else
static ba_mongo *ba_mongo_open(const char *uri) { (void)uri; return NULL; }
static void ba_mongo_close(ba_mongo *handle) { (void)handle; }
static char *ba_mongo_command(ba_mongo *handle, const char *database, const uint8_t *data, size_t length, int mode, int session) {
    (void)handle; (void)database; (void)data; (void)length; (void)mode; (void)session; return NULL;
}
static char *ba_mongo_transaction(ba_mongo *handle, int action) { (void)handle; (void)action; return NULL; }
static void ba_mongo_oid(char *output) { output[0] = 0; }
static void ba_mongo_free(char *data) { free(data); }
#endif
#endif
