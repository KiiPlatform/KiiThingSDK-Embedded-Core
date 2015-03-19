# KiiThingSDK Embedded

Kii Thing SDK designed for resource limited environment.
 - No dynamic memory allocation
 - No external library dependency.
 - Separated HTTP Layer can be implemented depending on environment.

## How to use

### Build examples

    make

#### Run linux example

    cd linux
    ./exampleapp --register

### Implement callback functions
Looking into kii.h, there are following callback functions needs implementation.

 - KII\_HTTPCB\_SET\_REQUEST\_LINE

   Prepare HTTP request line.
 - KII\_HTTPCB\_SET\_HEADER

   Prepare HTTP header. (called line by line)
 - KII\_HTTPCB\_SET\_BODY

   Prepare HTTP body.
 - KII\_HTTPCB\_EXECUTE

   Send request and receive response.
 - KII\_LOGGER

   Logging function used by SDK. Implementation is optional.

