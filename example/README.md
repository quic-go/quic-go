# Example to build server and client with http3
Welcome to the http3 library: the quic-go one. Here we would like to show examples for you to help
 you understand how to use it. There are two demos here, one is the echo one, and the other one is a 
seperated client and server to help you serve and make request with the quic-go.

## Echo
To run the [echo demo](./echo/echo.go), you could just run it:
```shell
go run echo.go
```
If you see this log, you are successful to run the echo demo.
```
Client: Sending 'foobar'
Server: Got 'foobar'
Client: Got 'foobar'
```
As you know that the echo here use the TLS as the encryption algorithm, where are they come from? 
They are generated inside the `echo.go` so you can quickly run it.å

## Server-and-client
In the last topic, you have used the echo to try http3. This topic will show you how to develop a 
simple server to serve with http3 and how to make request by http3 client.
To run the [server-and-client](./server-and-client) demo, you need to use two shell to run the 
following commands:
```shell
# under server-and-client/server
go run main.go
```

```shell
# under server-and-client/client
go run main.go
```
When you run the commands up without flags, the server listens on `https://localhost:6121` 
and client will make a request to `https://localhost:6121/` by default. The request will be 
processed by the handler set in server. You will receive a `400` response.  

The content showed above presents the default behavior to you. The client ca file is stored 
[here](server-and-client/client/testdata) and the server cert files are stored
[here](server-and-client/server/testdata). You can also specify your own files if you want.  

### More details about the server and client
- Server
  - set served domain
  If you want to serve many domains or specify another domain, you could add the domain list in 
  the command line like this, note that use the `https` prefix.
  ```shell
    # under server-and-client/server
    go run main.go https://localhost:8080 https://localhost:8081
  ```
- Client  
  - Specify the request destination  
    ```shell
    # under server-and-client/client
    go run main.go https://localhost:8080/subpath
  ```
