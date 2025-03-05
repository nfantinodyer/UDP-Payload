#compile the server file
gcc -o server_csen331 server_csen331.c

#compile the client file
gcc -o client csen331.c

#start the server
echo "starting server, run client with ./client in a new window"
./server_csen331