# The GOATs express backend

This is an express app, which uses socket.io for client-server communication and knex for connection and querybuilding of a postgres DB.
io_controller manages the communication with the client, db_controller manages the communication with the database. Jungle is a module that
represents the future blockchain. 

This is the current web2.0 platform backend and it's outdated by the p2p platform in the p-michael-b/apebase_data repository. That's a very lean 
fully functional p2p network. Based on Alexander Swensson's p2p net, but expanded by cryptography:

https://dev.to/swensson/create-a-p2p-network-with-node-from-scratch-1pah

Goal is to replace the socket.io communication with the p2p platform. 