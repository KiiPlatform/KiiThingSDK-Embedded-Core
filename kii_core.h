#ifndef _kii_
#define _kii_

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include "kii_socket_callback.h"

#ifndef KII_USE_CUSTOM_HTTP_CLIENT

#ifndef KII_SERVER_PORT
/** Port number of target service.
 *
 * This macro becomes activate, if KII_USE_CUSTOM_HTTP_CLIENT is not
 * defined.
 */
#define KII_SERVER_PORT 443
#endif

#ifndef KII_SOCKET_MAX_BUFF_SIZE
/** Maximum buffer size which socket sends or receives at a time.
 *
 * This is a maximum buffer size which is passed to
 * kii_http_context_t#send_cb. Value of third argument of
 * kii_http_context_t#send_cb equals to or is less than this size.
 *
 * This is also maximum buffer size which is passed to
 * kii_http_context_t#recv_cb. Value of third argument of
 * kii_http_context_t#recv_cb equals to or is less than this size.
 *
 * This macro becomes activate, if KII_USE_CUSTOM_HTTP_CLIENT is not
 * defined.
 */
#define KII_SOCKET_MAX_BUFF_SIZE 256
#endif

/** This is an enumeration to represent Kii SDK internal state.
 * Application programmers do not need to use this enumeration.
 */
typedef enum prv_kii_socket_state_t {
    PRV_KII_SOCKET_STATE_IDLE = 0,
    PRV_KII_SOCKET_STATE_CONNECT,
    PRV_KII_SOCKET_STATE_SEND,
    PRV_KII_SOCKET_STATE_RECV,
    PRV_KII_SOCKET_STATE_CLOSE
} prv_kii_socket_state_t;

#endif

/** bool type definition */
typedef enum kii_bool_t {
    KII_FALSE = 0,
    KII_TRUE
} kii_bool_t;

/** HTTP client code returned by callback implementation */
typedef enum kii_http_client_code_t {
    /** retrun this code when operation completed. */
    KII_HTTPC_OK = 0,
    /** return this code when operation failed. */
    KII_HTTPC_FAIL,
    /** return this code when operation is in progress.
     *  SDK calls the callback again until the operation
     *  completed or failed.
     */
    KII_HTTPC_AGAIN
} kii_http_client_code_t;

typedef struct kii_http_context_t
{
#ifdef KII_USE_CUSTOM_HTTP_CLIENT

    /** application specific context object.
     * used by HTTP callback implementations.
     *
     * This field becomes activate, if KII_USE_CUSTOM_HTTP_CLIENT is
     * defined.
     */
    void* app_context;

#else

    /** buffer used to communicate with KiiCloud.
     *  application allocate memory before calling apis.
     *
     * This field becomes activate, if KII_USE_CUSTOM_HTTP_CLIENT is not
     * defined.
     */
    char* buffer;

    /** size of buffer.
     *
     * This field becomes activate, if KII_USE_CUSTOM_HTTP_CLIENT is not
     * defined.
     */
    size_t buffer_size;

    /** total size of data to be sent.
     *
     * This field becomes activate, if KII_USE_CUSTOM_HTTP_CLIENT is not
     * defined.
     */
    size_t total_send_size;

    /** This is a private field for this SDK.
     * Application programmers must not use this field.
     *
     * This field becomes activate, if KII_USE_CUSTOM_HTTP_CLIENT is not
     * defined.
     */
    char* _body_position;

    /** This is a private field for this SDK.
     * Application programmers must not use this field.
     *
     * This field becomes activate, if KII_USE_CUSTOM_HTTP_CLIENT is not
     * defined.
     */
    size_t _sent_size;

    /** This is a private field for this SDK.
     * Application programmers must not use this field.
     *
     * This field becomes activate, if KII_USE_CUSTOM_HTTP_CLIENT is not
     * defined.
     */
    size_t _received_size;

    /** This is a private field for this SDK.
     * Application programmers must not use this field.
     *
     * This field becomes activate, if KII_USE_CUSTOM_HTTP_CLIENT is not
     * defined.
     */
    prv_kii_socket_state_t _socket_state;

    /** Host name to send HTTP request. You can connect to target
     * server with this host name.
     *
     * This field becomes activate, if KII_USE_CUSTOM_HTTP_CLIENT is not
     * defined.
     */
    const char* host;

    /** socket context used by the http client
     *
     * This field becomes activate, if KII_USE_CUSTOM_HTTP_CLIENT is not
     * defined.
     */
    kii_socket_context_t socket_context;

    /** socket close function callback.
     *
     * This field becomes activate, if KII_USE_CUSTOM_HTTP_CLIENT is not
     * defined.
     */

    KII_SOCKET_CONNECT_CB connect_cb;
    /** socket send function callback.
     *
     * This field becomes activate, if KII_USE_CUSTOM_HTTP_CLIENT is not
     * defined.
     */
    KII_SOCKET_SEND_CB send_cb;
    /** socket recv function callback.
     *
     * This field becomes activate, if KII_USE_CUSTOM_HTTP_CLIENT is not
     * defined.
     */
    KII_SOCKET_RECV_CB recv_cb;
    /** socket close function callback.
     *
     * This field becomes activate, if KII_USE_CUSTOM_HTTP_CLIENT is not
     * defined.
     */
    KII_SOCKET_CLOSE_CB close_cb;

#endif
} kii_http_context_t;

#ifdef KII_USE_CUSTOM_HTTP_CLIENT

/** callback for preparing HTTP request line.
 * application implement this callback with the HTTP client
 * in the target environment.
 *
 * This type becomes activate, if KII_USE_CUSTOM_HTTP_CLIENT is not
 * defined.
 *
 * @return KII_HTTPC_OK on success, KII_HTTPC_FAIL on error.<br>
 * do not return KII_HTTPC_AGAIN from this callback.
 * @param [in] http_context context object defined by application.
 * @param [in] method HTTP method
 * @param [in] host host name
 * @param [in] path resource path following to host in uri.
 */
typedef kii_http_client_code_t
        (*KII_HTTPCB_SET_REQUEST_LINE)(
                kii_http_context_t* http_context,
                const char* method,
                const char* host,
                const char* path);
/** callback for preparing HTTP request header.
 * application implement this callback with the HTTP client
 * in the target environment.<br>
 * this callback is called per one header line.
 *
 * This type becomes activate, if KII_USE_CUSTOM_HTTP_CLIENT is not
 * defined.
 *
 * @return KII_HTTPC_OK on success, KII_HTTPC_FAIL on error.<br>
 * do not return KII_HTTPC_AGAIN from this callback.
 * @param [in] http_context context object defined by application.
 * @param [in] key name of the header field.
 * @param [in] value value of the header field.
 */
typedef kii_http_client_code_t
        (*KII_HTTPCB_SET_HEADER)(
                kii_http_context_t* http_context,
                const char* key,
                const char* value);

/** callback to notify starting HTTP request body creation.
 * Applications implement this callback with the HTTP client in target
 * environment.<br>
 *
 * This type becomes activate, if KII_USE_CUSTOM_HTTP_CLIENT is not
 * defined.
 *
 * @return KII_HTTPC_OK on success, KII_HTTPC_FAIL on error.<br>
 * do not return KII_HTTPC_AGAIN from this callback.
 * @param [in] http_context context object defined by application.
 */
typedef kii_http_client_code_t
        (*KII_HTTPCB_APPEND_BODY_START)(kii_http_context_t* http_context);

/** callback for appending HTTP request body.
 * application implement this callback with the HTTP client
 * in the target environment.<br>
 *
 * This type becomes activate, if KII_USE_CUSTOM_HTTP_CLIENT is not
 * defined.
 *
 * @return KII_HTTPC_OK on success, KII_HTTPC_FAIL on error.<br>
 * do not return KII_HTTPC_AGAIN from this callback.
 * @param [in] http_context context object defined by application.
 * @param [in] body_data request body data.
 * @param [in] body_size request body data size.
 */
typedef kii_http_client_code_t
        (*KII_HTTPCB_APPEND_BODY)(
                kii_http_context_t* http_context,
                const char* body_data,
                size_t body_size);

/** callback to notify ending HTTP request body creation.
 * Applications implement this callback with the HTTP client in target
 * environment.<br>
 *
 * This type becomes activate, if KII_USE_CUSTOM_HTTP_CLIENT is not
 * defined.
 *
 * @return KII_HTTPC_OK on success, KII_HTTPC_FAIL on error.<br>
 * do not return KII_HTTPC_AGAIN from this callback.
 * @param [in] http_context context object defined by application.
 */
typedef kii_http_client_code_t
        (*KII_HTTPCB_APPEND_BODY_END)(kii_http_context_t* http_context);

/** callback for execution of HTTP request.
 * application implement this callback with the HTTP client
 * in the target environment.<br>
 *
 * This type becomes activate, if KII_USE_CUSTOM_HTTP_CLIENT is not
 * defined.
 *
 * @return KII_HTTPC_OK on success, KII_HTTPC_FAIL on error.<br>
 * KII_HTTPC_AGAIN can be retuned from this callback.<br>
 * This option may be useful if you execute kii_core_run() in function which
 * takes care of other events.
 * @param [out] response_code HTTP response code
 * @param [out] response_body pointer refers the HTTP response
 * body. This must be null-terminated string.
 */
typedef kii_http_client_code_t
        (*KII_HTTPCB_EXECUTE)(
                kii_http_context_t* http_context,
                int* response_code,
                char** response_body);
#endif

/** callback for logging.
 * SDK uses this function for logging.
 * If you want to enable logging,
 * set pointer of this function in kii_core_t#logger_cb.
 * Logging is only enabled in DEBUG build.
 */
typedef void
        (*KII_LOGGER)(
                const char* format,
                ...
                );

/** error code returned by SDK apis. */
typedef enum kii_error_code_t {
    KIIE_OK = 0,
    KIIE_FAIL
} kii_error_code_t;

/** represents state of SDK. */
typedef enum kii_state_t {
    /** SDK is idle. */
    KII_STATE_IDLE = 0,
    /** SDK is ready to execute kii_core_run() */
    KII_STATE_READY,
    /** SDK is executing request. kii_core_run() should be called to finish
     * operation
     */
    KII_STATE_EXECUTE
} kii_state_t;


/** represents author of SDK api. */
typedef struct kii_author_t
{
    /** ID of the author */
    char author_id[128];
    /** access token of the author */
    char access_token[128];
} kii_author_t;

/** object manages context of api execution. */
typedef struct kii_core_t
{
    /** Kii Cloud application id */
    char* app_id;
    /** Kii Cloud application key */
    char* app_key;
    /** Kii Cloud application host.
     *  value is depending on your site of application.
     *  Site JP : "api-jp.kii.com"
     *  Site US : "api.kii.com"
     *  Site CN : "api-cn2.kii.com"
     *  Site CN3: "api-cn3.kii.com"
     *  Site SG : "api-sg.kii.com"
     */
    char* app_host;
    /** HTTP response code.
     * value is set by implementation of KII_HTTPCB_EXECUTE
     */
    int response_code;
    /** HTTP response body 
     * value is set by implementation of KII_HTTPCB_EXECUTE
     */
    char* response_body;
    /** author of the api.
     * set author object before execute api requires authorization.
     */
    kii_author_t author;

    /** application's context object used by HTTP callback implementations. */
    kii_http_context_t http_context;

#ifdef KII_USE_CUSTOM_HTTP_CLIENT
    /** request line callback function pointer
     * Should be set before execute apis.
     *
     * This field becomes activate, if KII_USE_CUSTOM_HTTP_CLIENT is
     * defined.
     */
    KII_HTTPCB_SET_REQUEST_LINE http_set_request_line_cb;
    /** request header callback function pointer
     * Should be set before execute apis.
     *
     * This field becomes activate, if KII_USE_CUSTOM_HTTP_CLIENT is
     * defined.
     */
    KII_HTTPCB_SET_HEADER http_set_header_cb;

    /**
     * Notifying start of creation of request body callback function.
     * Should be set before execute APIs.
     *
     * This field becomes activate, if KII_USE_CUSTOM_HTTP_CLIENT is
     * defined.
     */
    KII_HTTPCB_APPEND_BODY_START http_append_body_start_cb;

    /**
     * Appending request body callback function.
     * Should be set before execute APIs.
     *
     * This field becomes activate, if KII_USE_CUSTOM_HTTP_CLIENT is
     * defined.
     */
    KII_HTTPCB_APPEND_BODY http_append_body_cb;

    /**
     * Notifying end of creation of request body callback function.
     * Should be set before execute APIs.
     *
     * This field becomes activate, if KII_USE_CUSTOM_HTTP_CLIENT is
     * defined.
     */
    KII_HTTPCB_APPEND_BODY_END http_append_body_end_cb;

    /** execute HTTP request function pointer
     * Should be set before execute apis.
     *
     * This field becomes activate, if KII_USE_CUSTOM_HTTP_CLIENT is
     * defined.
     */
    KII_HTTPCB_EXECUTE http_execute_cb;

#endif

    /** logging callback function pointer */
    KII_LOGGER logger_cb;

    char _http_request_path[256];

    kii_state_t _state;

    size_t _content_length;
} kii_core_t;


/** represents scope of bucket/ topic. */
typedef enum kii_scope_type_t {
    KII_SCOPE_APP,
    KII_SCOPE_USER,
    KII_SCOPE_GROUP,
    KII_SCOPE_THING
} kii_scope_type_t;

/** represents bucket */
typedef struct kii_bucket_t {
    kii_scope_type_t scope;
    char* scope_id;
    char* bucket_name;
} kii_bucket_t;

/** represents topic */
typedef struct kii_topic_t {
    kii_scope_type_t scope;
    char* scope_id;
    char* topic_name;
} kii_topic_t;

/** Initializes Kii SDK
 *  \param [inout] kii core sdk instance.
 *  \param [in] site the input of site name,
 *  should be one of "CN", "CN3", "JP", "US", "SG"
 *  \param [in] app_id the input of Application ID
 *  \param [in] app_key the input of Application Key
 *  \return  KIIE_OK:success, KIIE_FAIL: failure
 */
kii_error_code_t kii_core_init(
        kii_core_t* kii,
        const char* site,
        const char* app_id,
        const char* app_key);

/** obtain current state of SDK.
 * @return state of SDK.
 */
kii_state_t kii_core_get_state(kii_core_t* kii);

/** execute HTTP request.
 * application calls this method again
 * until the state becomes KII_STATE_IDLE,
 * @return result of execution.
 */
kii_error_code_t kii_core_run(kii_core_t* kii);

/** prepare request of regiser thing.
 * This function requires JSON string as thing_data argument. In this
 * JSON string, you can add custom properties. "_vendorThingID" and
 * "_password" properties are required in this JSON string.  after
 * this method succeeded, state of SDK becomes KII_STATE_READY.<br>
 * execute kii_core_run() to send the request to Kii Cloud.
 * @return result of preparation.
 * @param [in] kii SDK object.
 * @param [in] thing_data JSON object represents thing to be registered.<br>
 * for details of format, please refer to<br>
 * http://documentation.kii.com/rest/apps-collection/application/thing-collection/#method-thingsResourceType-POST
 * <br>This must be null terminated.
 */
kii_error_code_t
kii_core_register_thing(kii_core_t* kii,
        const char* thing_data);

/** prepare request of regiser thing.
 * Unlike kii_core_register_thing(kii_core_t*, const char*), this
 * function only register "_vendorThingID", "_password" and
 * "_thingType" fields.  after this method succeeded, state of SDK
 * becomes KII_STATE_READY.<br> execute kii_core_run() to send the request
 * to Kii Cloud.
 *
 * vendor_thing_id, password and thing_type must be escaped in JSON
 * manner. http://www.json.org/
 *
 * @return result of preparation.
 * @param [in] kii SDK object.
 * @param [in] vendor_thing_id the thing identifier given by vendor.
 * @param [in] password - the password of the thing given by vendor.
 * @param [in] thing_type the type of the thing given by vendor. This
 * is optional. Can be null.
 */
kii_error_code_t
kii_core_register_thing_with_id(
        kii_core_t* kii,
        const char* vendor_thing_id,
        const char* password,
        const char* thing_type);

/** prepare request of thing authentication.
 * after this method succeeded, state of SDK becomes KII_STATE_READY.<br>
 * execute kii_core_run() to send the request to Kii Cloud.
 *
 * vendor_thing_id and password must be escaped in JSON
 * manner. http://www.json.org/
 *
 * @return result of preparation.
 * @param [in] kii SDK object.
 * @param [in] vendor_thing_id thing id given by vendor on registration.
 * @param [in] password password of thing given by vendor on registration.
 */
kii_error_code_t
kii_core_thing_authentication(kii_core_t* kii,
        const char* vendor_thing_id,
        const char* password);

/** prepare request of thing authentication with http body.
 * after this method succeeded, state of SDK becomes KII_STATE_READY.<br>
 * execute kii_core_run() to send the request to Kii Cloud.
 *
 * @return result of preparation.
 * @param [in] kii SDK object.
 * @param [in] body body of authentication request.
 */
kii_error_code_t
kii_core_thing_authentication_with_body(kii_core_t* kii,
        const char* body);

/** prepare request of create object.
 * after this method succeeded, state of SDK becomes KII_STATE_READY.<br>
 * execute kii_core_run() to send the request to Kii Cloud.
 * @return result of preparation.
 * @param [in] kii SDK object.
 * @param [in] bucket to which object belongs.
 * @param [in] object_data key-value of object data in JSON.
 * This must be null-terminated byte string.
 * @param [in] opt_object_content_type content type of object.<br>
 * if NULL is given, "application/json" is used.
 */
kii_error_code_t
kii_core_create_new_object(
        kii_core_t* kii,
        const kii_bucket_t* bucket,
        const char* object_data,
        const char* opt_object_content_type
        );

/** prepare request of create object with id.
 * after this method succeeded, state of SDK becomes KII_STATE_READY.<br>
 * execute kii_core_run() to send the request to Kii Cloud.
 * @return result of preparation.
 * @param [in] kii SDK object.
 * @param [in] bucket to which object belongs.
 * @param [in] object_id id of the object.
 * @param [in] object_data key-value of object data in JSON.
 * This must be null-terminated byte string.
 * @param [in] opt_object_content_type content type of object.<br>
 * if NULL is given, "application/json" is used.
 */
kii_error_code_t
kii_core_create_new_object_with_id(
        kii_core_t* kii,
        const kii_bucket_t* bucket,
        const char* object_id,
        const char* object_data,
        const char* opt_object_content_type
        );

/** prepare request of patch object.
 * after this method succeeded, state of SDK becomes KII_STATE_READY.<br>
 * execute kii_core_run() to send the request to Kii Cloud.
 * @return result of preparation.
 * @param [in] kii SDK object.
 * @param [in] bucket to which object belongs.
 * @param [in] object_id id of the object.
 * @param [in] patch_data key-value of patch data in JSON.<br>
 * key-value pair which is not contained this patch
 * is not updated after execution.
 * <br>This must be null-terminated byte string.
 * @param [in] opt_etag etag of the object. if this value is specified,
 * if-match header is sent to Kii Cloud. in a result,
 * patch request only success when the version of the object in client and
 * server matches.<br>
 * If NULL is given, no version check is executed and patch is forcibly applied.
 */
kii_error_code_t
kii_core_patch_object(
        kii_core_t* kii,
        const kii_bucket_t* bucket,
        const char* object_id,
        const char* patch_data,
        const char* opt_etag);

/** prepare request of replace object.
 * after this method succeeded, state of SDK becomes KII_STATE_READY.<br>
 * execute kii_core_run() to send the request to Kii Cloud.
 * @return result of preparation.
 * @param [in] kii SDK object.
 * @param [in] bucket to which object belongs.
 * @param [in] object_id id of the object.
 * @param [in] replace_data key-value of replacement data in JSON.<br>
 * key-value pair which is not containd this data is deleted after execution.
 * <br>This must be null-terminated byte string.
 * @param [in] opt_etag etag of the object. if this value is specified,
 * if-match header is sent to Kii Cloud. in a result,
 * replace request only success when the version of the object in client and
 * server matches.<br>
 * If NULL is given,
 * no version check is executed and replace is forcibly applied.
 */
kii_error_code_t
kii_core_replace_object(
        kii_core_t* kii,
        const kii_bucket_t* bucket,
        const char* object_id,
        const char* replace_data,
        const char* opt_etag);

/** prepare request of get object.
 * after this method succeeded, state of SDK becomes KII_STATE_READY.<br>
 * execute kii_core_run() to send the request to Kii Cloud.
 * @return result of preparation.
 * @param [in] kii SDK object.
 * @param [in] bucket to which object belongs.
 * @param [in] object_id id of the object.
 */
kii_error_code_t
kii_core_get_object(
        kii_core_t* kii,
        const kii_bucket_t* bucket,
        const char* object_id);

/** prepare request of delete object.
 * after this method succeeded, state of SDK becomes KII_STATE_READY.<br>
 * execute kii_core_run() to send the request to Kii Cloud.
 * @return result of preparation.
 * @param [in] kii SDK object.
 * @param [in] bucket object to be created.
 * @param [in] object_id id of the object.
 */
kii_error_code_t
kii_core_delete_object(
        kii_core_t* kii,
        const kii_bucket_t* bucket,
        const char* object_id);

/** prepare request of subscribe bucket.
 * after this method succeeded, state of SDK becomes KII_STATE_READY.<br>
 * execute kii_core_run() to send the request to Kii Cloud.
 * after the execution of request succeeded, you can receive push notification
 * when event happens in the bucket.
 * @return result of preparation.
 * @param [in] kii SDK object.
 * @param [in] bucket to be subscribed.
 */
kii_error_code_t
kii_core_subscribe_bucket(kii_core_t* kii,
        const kii_bucket_t* bucket);

/** prepare request of subscribe bucket.
 * after this method succeeded, state of SDK becomes KII_STATE_READY.<br>
 * execute kii_core_run() to send the request to Kii Cloud.
 * @return result of preparation.
 * @param [in] kii SDK object.
 * @param [in] bucket to be unsubscribed.
 */
kii_error_code_t
kii_core_unsubscribe_bucket(kii_core_t* kii,
        const kii_bucket_t* bucket);

/** prepare request of create topic.
 * after this method succeeded, state of SDK becomes KII_STATE_READY.<br>
 * execute kii_core_run() to send the request to Kii Cloud.
 * after execution of the request succeeded, you can subscribe topic to receive
 * message sent to the topic.
 * @return result of preparation.
 * @param [in] kii SDK object.
 * @param [in] topic to be created.
 */
kii_error_code_t
kii_core_create_topic(kii_core_t* kii,
        const kii_topic_t* topic);

/** prepare request of delete topic.
 * after this method succeeded, state of SDK becomes KII_STATE_READY.<br>
 * execute kii_core_run() to send the request to Kii Cloud.
 * @return result of preparation.
 * @param [in] kii SDK object.
 * @param [in] topic to be deleted.
 */
kii_error_code_t
kii_core_delete_topic(kii_core_t* kii,
        const kii_topic_t* topic);

/** prepare request of subscribe topic.
 * after this method succeeded, state of SDK becomes KII_STATE_READY.<br>
 * execute kii_core_run() to send the request to Kii Cloud.
 * after the execution of request succeeded, you can receive push notification
 * when the message is sent to the topic.
 * @return result of preparation.
 * @param [in] kii SDK object.
 * @param [in] topic to be subscribed.
 */
kii_error_code_t
kii_core_subscribe_topic(kii_core_t* kii,
        const kii_topic_t* topic);

/** prepare request of unsubscribe topic.
 * after this method succeeded, state of SDK becomes KII_STATE_READY.<br>
 * execute kii_core_run() to send the request to Kii Cloud.
 * @return result of preparation.
 * @param [in] kii SDK object.
 * @param [in] topic to be unsubscribed.
 */
kii_error_code_t
kii_core_unsubscribe_topic(kii_core_t* kii,
        const kii_topic_t* topic);

/** prepare request of install push for thing.
 * after this method succeeded, state of SDK becomes KII_STATE_READY.<br>
 * execute kii_core_run() to send the request to Kii Cloud.
 * application get installationRegistrationID field in the response body to
 * obtain MQTT endpoint.
 * for details of response, please refer to<br>
 * http://documentation.kii.com/rest/apps-collection/application/installations/
 * @return result of preparation.
 * @param [in] kii SDK object.
 * @param [in] development flag indicate whether the installation is
 * development of production.
 */
kii_error_code_t
kii_core_install_thing_push(kii_core_t* kii,
        kii_bool_t development);

/** prepare request of get MQTT endpoint.
 * after this method succeeded, state of SDK becomes KII_STATE_READY.<br>
 * execute kii_core_run() to send the request to Kii Cloud.
 * application get the information of MQTT endpoint from the response body
 * to connect and receive push notification sent from Kii Cloud
 * for details of response, please refer to<br>
 * http://documentation.kii.com/rest/#notification_management-manage_the_user_thing_device_installation-get_the_mqtt_endpoint_information
 * @return result of preparation.
 * @param [in] kii SDK object.
 * @param [in] installation_id obtained from response body of
 * kii_install_thing_push()
 */
kii_error_code_t
kii_core_get_mqtt_endpoint(kii_core_t* kii,
        const char* installation_id);

/** call other REST API by http request.
 * @return result of preparation.
 * @param [in] kii SDK object.
 * @param [in] http_method method of http request.
 * @param [in] resource_path resource path of http request.
 * @param [in] http_body body data of http request.
 * @param [in] body_size size of http_body.
 * @param [in] content_type content type of http_body.
 * @param [in] header append headers of http request.
 * one header value like "{key}:{value}".
 */
kii_error_code_t
kii_core_api_call(
        kii_core_t* kii,
        const char* http_method,
        const char* resource_path,
        const char* http_body,
        size_t body_size,
        const char* content_type,
        char* header,
        ...);

/** start to create request for REST API.
 *
 * Between this function and kii_core_api_call_end(kii_core_t*), you
 * can call kii_core_api_call_append_body(kii_core_t*, const char*
 * size_t) and kii_core_api_call_append_header(kii_core_t*, const
 * char*, const char*) any number of times.
 *
 * @param [in] kii SDK object.
 * @param [in] http_method method of http request.
 * @param [in] resource_path resource path of http request.
 * @param [in] content_type content type of http_body.
 * @param [in] set_authentication_header a flag to set or not
 * authentication header.
 * @return result of preparation. if KIIE_OK, preparation is
 * succeeded, otherwise failed
 */
kii_error_code_t kii_core_api_call_start(
        kii_core_t* kii,
        const char* http_method,
        const char* resource_path,
        const char* content_type,
        kii_bool_t set_authentication_header);

/** append request body.
 *
 * This function must be called between
 * kii_core_api_call_start(kii_core_t*, const char*, const char*,
 * const char*, kii_bool_t) and kii_core_api_call_end(kii_core_t*).
 *
 * @param [in] kii SDK object.
 * @param [in] body_data appended body data.
 * @param [in] body_size appended body data size.
 * @return result of appending. if KIIE_OK appending is succeeded,
 * otherwise failed.
 */
kii_error_code_t kii_core_api_call_append_body(
        kii_core_t* kii,
        const char* body_data,
        size_t body_size);

/** append request header.
 *
 * This function must be called between
 * kii_core_api_call_start(kii_core_t*, const char*, const char*,
 * const char*, kii_bool_t) and kii_core_api_call_end(kii_core_t*).
 *
 * @param [in] kii SDK object.
 * @param [in] key key of http header.
 * @param [in] value value of http header.
 * @return result of appending. if KIIE_OK appending is succeeded,
 * otherwise failed.
 */
kii_error_code_t
kii_core_api_call_append_header(
        kii_core_t* kii,
        const char* key,
        const char* value);

/** end of creation of request for REST API.
 *
 * If you call kii_core_api_call_start(kii_core_t*, const char*, const
 * char*, const char*, kii_bool_t), you must call this function at the
 * end of creation of request.
 *
 * @param [in] kii SDK object.
 * @return result of closing request creation if KIIE_OK it is
 * succeeded, otherwise failed.
 */
kii_error_code_t kii_core_api_call_end(kii_core_t* kii);

#ifdef __cplusplus
}
#endif

#endif
/* vim:set ts=4 sts=4 sw=4 et fenc=UTF-8 ff=unix: */
