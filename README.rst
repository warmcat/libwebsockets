
Useful tips for using `libwebsockets`
=====================================

Maximum number of clients
-------------------------
There is a hard limit on the maximum number of clients the library will accept and by default it is set to **100**.
This limit can be changed by modifying the **MAX_CLIENTS** preprocessor macro in the file
**lib/private-libwebsockets.h**. The higher the limit the more memory the library will allocate at startup.

SSL performance
---------------
It is recommended to tweak the ciphers allowed on secure connections for performance reasons,
otherwise a slow algorithm may be selected by the two endpoints and the server could expend most of its time just
encrypting and decrypting data, severely limiting the amount of messages it will be able to handle per second.
To limit the ciphers supported on secure connections you should modify the preprocessor macro **CIPHERS_LIST_STRING**
in the file **lib/private-libwebsockets.h**. For example::

    #define CIPHERS_LIST_STRING "RC4-MD5:RC4-SHA:AES128-SHA:AES256-SHA:HIGH:!DSS:!aNULL"

Other tweaks
------------
There are several preprocessor macros that could be tweaked to reduce memory usage,
to increase performance or to change the behaviour of the library to suit your needs,
they are all located in the file **lib/private-libwebsockets.h**.

Big frames
----------
The library process data from the sockets in chunks of **4KB** (defined by the macro **MAX_USER_RX_BUFFER**),
these chunks will be passed to the client callback as **LWS_CALLBACK_RECEIVE**.
If you want to know whether you have all the data for the current frame you need to use the function
**libwebsockets_remaining_packet_payload**.

Fragmented messages
-------------------
To support fragmented messages you need to check for the final frame of a message with
**libwebsocket_is_final_fragment**. This check can be combined with **libwebsockets_remaining_packet_payload**
to gather the whole contents of a message like in this example::

    case LWS_CALLBACK_RECEIVE:
    {
        Client * const client = (Client *)user;
        const size_t remaining = libwebsockets_remaining_packet_payload(wsi);
        if (0 == remaining &&
            libwebsocket_is_final_fragment(wsi))
        {
            if (client->HasFragments())
            {
                client->AppendMessageFragment(in, len, 0);
                in = (void *)client->GetMessage();
                len = client->GetMessageLength();
            }

            client->ProcessMessage((char *)in, len, wsi);

            client->ResetMessage();
        }
        else
        {
            client->AppendMessageFragment(in, len, remaining);
        }
    }
    break;

HTTP requests
-------------
If your server is going to support regular HTTP requests by handling **LWS_CALLBACK_HTTP** it is recommended to
**return 1** as the result of the callback after you write the response,
this will tell the library to automatically close the connection.
Closing the connection will liberate an slot for another HTTP request,
otherwise it would be up to the browser to close the connection,
which could be an issue because the library has a hard limit on the number of open connections, as explained before.
