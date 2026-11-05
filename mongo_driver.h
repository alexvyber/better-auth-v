#ifndef BETTER_AUTH_MONGO_DRIVER_H
#define BETTER_AUTH_MONGO_DRIVER_H
#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
typedef struct ba_mongo ba_mongo;
typedef char *(*ba_mongo_transaction_callback)(void *);
#ifdef BA_ENABLE_MONGODB
#include <mongoc/mongoc.h>
#include <pthread.h>
struct ba_mongo {
    mongoc_client_t *client;
    mongoc_client_session_t *session;
    int active, txn_valid;
    int64_t txn_number, commits, aborts;
    int64_t last_abort_code;
    int last_abort_retryable;
    char last_abort_message[512];
};
static void ba_mongo_command_started(const mongoc_apm_command_started_t *event) {
    ba_mongo *handle = mongoc_apm_command_started_get_context(event);
    const char *name = mongoc_apm_command_started_get_command_name(event);
    if (strcmp(name, "commitTransaction") == 0) handle->commits++;
    if (strcmp(name, "abortTransaction") == 0) handle->aborts++;
    if (!handle->session) return;
    const bson_t *command = mongoc_apm_command_started_get_command(event);
    bson_iter_t iter;
    if (!bson_iter_init_find(&iter, command, "lsid") || !BSON_ITER_HOLDS_DOCUMENT(&iter)) return;
    uint32_t length; const uint8_t *bytes;
    bson_iter_document(&iter, &length, &bytes);
    bson_t lsid;
    bson_init_static(&lsid, bytes, length);
    if (!bson_equal(&lsid, mongoc_client_session_get_lsid(handle->session))) return;
    if (bson_iter_init_find(&iter, command, "txnNumber") && BSON_ITER_HOLDS_INT64(&iter)) {
        handle->txn_number = bson_iter_int64(&iter);
        handle->txn_valid = 1;
    }
}
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
    mongoc_apm_callbacks_t *callbacks = mongoc_apm_callbacks_new();
    mongoc_apm_set_command_started_cb(callbacks, ba_mongo_command_started);
    mongoc_client_set_apm_callbacks(client, callbacks, handle);
    mongoc_apm_callbacks_destroy(callbacks);
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
typedef struct {
    ba_mongo *handle;
    ba_mongo_transaction_callback callback;
    void *context;
    int commit_attempted;
} ba_mongo_managed_context;
static bool ba_mongo_managed_callback(mongoc_client_session_t *session, void *data, bson_t **reply, bson_error_t *error) {
    (void)session;
    ba_mongo_managed_context *context = data;
    context->handle->active = 1;
    context->commit_attempted = 0;
    const char *failure = context->callback(context->context);
    context->handle->active = 0;
    if (!failure) { context->commit_attempted = 1; return true; }
    *reply = bson_new_from_json((const uint8_t *)failure, -1, error);
    if (!*reply) return false;
    bson_iter_t iter;
    const char *message = "Native transaction callback failed";
    if (bson_iter_init_find(&iter, *reply, "errmsg") && BSON_ITER_HOLDS_UTF8(&iter)) message = bson_iter_utf8(&iter, NULL);
    bson_set_error(error, MONGOC_ERROR_TRANSACTION, 1, "%s", message);
    return false;
}
static void ba_mongo_abort_unsettled(ba_mongo *handle) {
    if (!handle->session || !handle->txn_valid) return;
    // A failed commit can make the driver report no active transaction while
    // leaving one open on the server. Public APM metadata supplies the exact
    // session/transaction number without depending on private driver structs.
    bson_t command = BSON_INITIALIZER;
    BSON_APPEND_INT32(&command, "abortTransaction", 1);
    BSON_APPEND_INT64(&command, "txnNumber", handle->txn_number);
    BSON_APPEND_BOOL(&command, "autocommit", false);
    for (int attempt = 0; attempt < 2; attempt++) {
        bson_error_t error = {0}; bson_t reply = BSON_INITIALIZER;
        bson_t options = BSON_INITIALIZER;
        // Attach the explicit session through the public driver API. Embedding
        // lsid in the command itself would duplicate the driver's lsid field.
        bool ok = mongoc_client_session_append(handle->session, &options, &error) &&
            mongoc_client_command_with_opts(handle->client, "admin", &command, NULL, &options, &reply, &error);
        bson_destroy(&options);
        bson_iter_t iter; int64_t code = 0;
        if (bson_iter_init_find(&iter, &reply, "code")) code = bson_iter_as_int64(&iter);
        bool retry = mongoc_error_has_label(&reply, "RetryableWriteError") || error.domain == MONGOC_ERROR_STREAM || error.domain == MONGOC_ERROR_SERVER_SELECTION;
        handle->last_abort_code = code;
        handle->last_abort_retryable = retry;
        bson_snprintf(handle->last_abort_message, sizeof(handle->last_abort_message), "%s", error.message);
        bson_destroy(&reply);
        if (ok || code == 251 || code == 256 || !retry) break;
    }
    bson_destroy(&command);
}
static char *ba_mongo_managed(ba_mongo *handle, ba_mongo_transaction_callback callback, void *context) {
    bson_error_t error = {0}; bson_t reply = BSON_INITIALIZER;
    if (handle->session) mongoc_client_session_destroy(handle->session);
    handle->session = mongoc_client_start_session(handle->client, NULL, &error);
    handle->active = 0; handle->txn_valid = 0;
    handle->last_abort_code = 0; handle->last_abort_retryable = 0; handle->last_abort_message[0] = '\0';
    bool ok = false;
    ba_mongo_managed_context data = {handle, callback, context, 0};
    if (handle->session) ok = mongoc_client_session_with_transaction(handle->session, ba_mongo_managed_callback, NULL, &data, &reply, &error);
    if (!ok && data.commit_attempted) ba_mongo_abort_unsettled(handle);
    if (!ok && handle->last_abort_code && handle->last_abort_code != 251 && handle->last_abort_code != 256) {
        BSON_APPEND_UTF8(&reply, "abortCleanupError", handle->last_abort_message);
    }
    char *out = ba_mongo_result(ok, &reply, &error);
    bson_destroy(&reply);
    if (handle->session) mongoc_client_session_destroy(handle->session);
    handle->session = NULL; handle->active = 0; handle->txn_valid = 0;
    return out;
}
static char *ba_mongo_transaction_stats(ba_mongo *handle) {
    bson_t reply = BSON_INITIALIZER;
    BSON_APPEND_INT64(&reply, "commits", handle->commits);
    BSON_APPEND_INT64(&reply, "aborts", handle->aborts);
    BSON_APPEND_INT64(&reply, "lastAbortCode", handle->last_abort_code);
    BSON_APPEND_BOOL(&reply, "lastAbortRetryable", handle->last_abort_retryable);
    BSON_APPEND_UTF8(&reply, "lastAbortMessage", handle->last_abort_message);
    char *out = ba_mongo_result(1, &reply, NULL);
    bson_destroy(&reply); return out;
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
static char *ba_mongo_managed(ba_mongo *handle, ba_mongo_transaction_callback callback, void *context) { (void)handle; (void)callback; (void)context; return NULL; }
static char *ba_mongo_transaction_stats(ba_mongo *handle) { (void)handle; return NULL; }
static void ba_mongo_oid(char *output) { output[0] = 0; }
static void ba_mongo_free(char *data) { free(data); }
#endif
#endif
