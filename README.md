# cs4400-serverhandout
CS4400 A6 - Concurrent Web Server by Alex Cao
This is the implementation of a concurrent friend-list server.
- The server uses a dictionary data structure to keep track the friend list.
- The server can accept request from client to add friends, unfriend and list all the friends of a user.
- Part of the server’s functionality involves acting as a client to introduce friends from other servers that implement the same protocol.
-------------------------------------------------------
To run the server:
    make
    ./friendlist <port>

To connect the server:
    http://localhost:<port>/

Server queries you can use:
1. /friends?user=‹user› 
    Returns the friends of ‹user›
2. /befriend?user=‹user›&friends=‹friends› 
    Adds each user in ‹friends› as a friend of ‹user›, which implies adding ‹user› as a friend of each user in ‹friends› (use "%0A" to seperate multiple friends).
3. /unfriend?user=‹user›&friends=‹friends› 
    Removes each user in ‹friends› as a friend of ‹user› and vice versa.
4. /introduce?user=‹user›&friend=‹friend›&host=‹host›&port=‹port› 
    Contacts a friend-list server running on ‹host› at ‹port› to get all of the friends of ‹friend›, and adds ‹friend› plus all of ‹friend›’s friends as friends of ‹user› and vice versa.


