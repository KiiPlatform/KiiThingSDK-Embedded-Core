#include <WiFi.h>
#include <WiFiClient.h>
#include <WiFiServer.h>
#include <aJSON.h>
#include "kii.h"
#include "http.h"

// Response data/funcs
struct HttpResponse {
  String body;
  int code;
};

static void* response_realloc(void* opaque, void* ptr, int size)
{
  return realloc(ptr, size);
}

static void response_body(void* opaque, const char* data, int size)
{
  HttpResponse* response = (HttpResponse*)opaque;
  response->body += data;

}

static void response_header(void* opaque, const char* ckey, int nkey, const char* cvalue, int nvalue)
{ /* example doesn't care about headers */
}

static void response_code(void* opaque, int code)
{
  HttpResponse* response = (HttpResponse*)opaque;
  response->code = code;
}

static const http_funcs responseFuncs = {
  response_realloc,
  response_body,
  response_header,
  response_code,
};

// your network name also called SSID
char ssid[] = "WL02";
// your network password
char password[] = "synclorewl02";
// your network key Index number (needed only for WEP)
int keyIndex = 0;

typedef struct context_t
{

  int sock;
  char* buff;
  size_t buff_size;
  char host[256];
  int last_chunk;
  int sent_size;
  int received_size;
} 
context_t;
/* HTTP Callback functions */
kii_http_client_code_t
request_line_cb(
void* http_context,
const char* method,
const char* host,
const char* path)
{
  context_t* ctx = (context_t*)http_context;
  char* reqBuff = ctx->buff;
  strncpy(ctx->host, host, strlen(host));
  // TODO: prevent overflow.
  sprintf(reqBuff, "%s https://%s/%s HTTP/1.1\r\n", method, host, path);

  return KII_HTTPC_OK;
}
kii_http_client_code_t
header_cb(
void* http_context,
const char* key,
const char* value)
{
  // TODO: prevent overflow.
  char* reqBuff = ((context_t*)http_context)->buff;
  strcat(reqBuff, key);
  strcat(reqBuff, ":");
  strcat(reqBuff, value);
  strcat(reqBuff, "\r\n");
  return KII_HTTPC_OK;
}
kii_http_client_code_t
body_cb(
void* http_context,
const char* body_data)
{
  // TODO: prevent overflow.
  char* reqBuff = ((context_t*)http_context)->buff;
  strcat(reqBuff, "\r\n");
  strcat(reqBuff, body_data);
  return KII_HTTPC_OK;
}
kii_http_client_code_t
execute_cb(
void* http_context,
int* response_code,
char** response_body)
{

  context_t* ctx = (context_t*)http_context;
  WiFiClient http;
  char buf[1025];
  int i;
  size_t total = 0;
  HttpResponse response;
  response.code = 0;

  http_roundtripper rt;
  http_init(&rt, responseFuncs, &response);

  Serial.println("execute: ");
  Serial.println(ctx->buff);
  if (http.sslConnect(ctx->host, 443)) 
  {
    http.println(ctx->buff);
    String resp = "";
    Serial.println("Waiting for response...");
    while (http.connected()) {

      i = http.read((uint8_t *)buf, 1024);
      buf[i] = '\0';

      total += i;
      resp+=buf;
      int read;
      http_data(&rt, buf, i, &read);
    }

    http_free(&rt);
    
    *response_code = response.code;
    char *temp = new char[response.body.length()+1];
    strcpy(temp, response.body.c_str());
    *response_body = temp;
    delete temp;
  }
  else {
    Serial.println("Error connecting ");
  }
  return KII_HTTPC_OK;
}

void printWifiStatus();
kii_thing_t parse_thing(char*);
kii_error_t parse_error(char*);
void setup() {
  //Initialize serial and wait for port to open:
  Serial.begin(115200);
  char buf[1025];
  int i;
  size_t total = 0;
  // attempt to connect to Wifi network:
  Serial.print("Attempting to connect to Network named: ");
  // print the network name (SSID);
  Serial.println(ssid);
  // Connect to WPA/WPA2 network. Change this line if using open or WEP network:
  WiFi.begin(ssid, password);

  while ( WiFi.status() != WL_CONNECTED) {
    // print dots while we wait to connect
    Serial.print(".");
    delay(300);
  }

  Serial.println("\nYou're connected to the network");
  Serial.println("Waiting for an ip address");

  while (WiFi.localIP() == INADDR_NONE) {
    // print dots while we wait for an ip addresss
    Serial.print(".");
    delay(300);
  }

  Serial.println("\nIP Address obtained");
  printWifiStatus();
  context_t ctx;
  kii_t kii;
  kii_state_t state;
  kii_error_code_t err;
  char buff[4096];
  char thingData[] = "{\"_vendorThingID\":\"thing-7777-www-xxx-yyy-zzz\", \"_password\":\"1234\"}";

  /* Initialization */
  memset(&kii, 0x00, sizeof(kii));
  kii.app_id = "9ab34d8b";
  kii.app_key = "7a950d78956ed39f3b0815f0f001b43b";
  kii.app_host = "api-jp.kii.com";
  kii.buffer = buff;
  kii.buffer_size = 4096;

  kii.http_context = &ctx;
  kii.http_set_request_line_cb = request_line_cb;
  kii.http_set_header_cb = header_cb;
  kii.http_set_body_cb = body_cb;
  kii.http_execute_cb = execute_cb;

  memset(&ctx, 0x00, sizeof(ctx));
  /* share the request and response buffer.*/
  ctx.buff = buff;
  ctx.buff_size = 4096;
  /* Register Thing */
  err = kii_register_thing(&kii, thingData);
  Serial.print("request:\n");

  if (err != KIIE_OK) {
    Serial.println("execution failed\n");
    return ;
  }
  do {
    state = kii_get_state(&kii);
    err = kii_run(&kii);
    state = kii_get_state(&kii);
  } 
  while (state != KII_STATE_IDLE);
  Serial.println("========response========");
  Serial.println(kii.buffer);
  Serial.println("========response========\n");
  Serial.print("response_code:");
  Serial.println( kii.response_code);
  Serial.println("response_body:");
  Serial.println( kii.response_body);
  kii_thing_t thing;
  if(kii.response_code==201)
  {
    thing=parse_thing(kii.response_body);
    Serial.print("thingID:");
    Serial.println(thing.thing_id);
    Serial.print("access token:");
    Serial.println(thing.access_token);
    
  }else
  {
    kii_error_t error = parse_error(kii.response_body);
    Serial.print("error_code:");
    Serial.println(error.error_code);
  }
}

void loop()
{

}

kii_thing_t parse_thing(char* thing_data)
{
  kii_thing_t thing;
  aJsonObject* root = aJson.parse(thing_data);
  if(root != NULL){
    aJsonObject* thingID = aJson.getObjectItem(root, "_thingID"); 
    aJsonObject* vendorID = aJson.getObjectItem(root, "_vendorThingID"); 
    aJsonObject* accessToken = aJson.getObjectItem(root, "_accessToken"); 
    thing.vendor_id = vendorID!=NULL?vendorID->valuestring:NULL;
    thing.thing_id = thingID!=NULL?thingID->valuestring:NULL;
    thing.access_token = accessToken!=NULL?accessToken->valuestring:NULL;
  }
  return thing;
}
  
kii_error_t parse_error(char* error_data)
{
  kii_error_t error;
  aJsonObject* root = aJson.parse(error_data);
  if(root != NULL){
    aJsonObject* errorCode = aJson.getObjectItem(root, "errorCode"); 
    aJsonObject* errorMsg = aJson.getObjectItem(root, "message"); 
    error.error_code = errorCode!=NULL?errorCode->valuestring:NULL;
    error.error_message = errorMsg!=NULL?errorMsg->valuestring:NULL;
  }
  return error;
}
  
void printWifiStatus() {
  // print the SSID of the network you're attached to:
  Serial.print("SSID: ");
  Serial.println(WiFi.SSID());

  // print your WiFi shield's IP address:
  IPAddress ip = WiFi.localIP();
  Serial.print("IP Address: ");
  Serial.println(ip);

  // print the received signal strength:
  long rssi = WiFi.RSSI();
  Serial.print("signal strength (RSSI):");
  Serial.print(rssi);
  Serial.println(" dBm");
}




