#include "asgn2_helper_funcs.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <errno.h>
#include <sys/stat.h>

#define BUFFER_SIZE 4096

// **Request Format: method (at most 8 chars), URI (at most 64, including /, so 63), version
#define REX "^([a-zA-Z]{1,8}) /([a-zA-Z0-9.-]{1,63}) (HTTP/[0-9]\\.[0-9])\r\n"

// **Header Format: key (at most 128 characters), value (at most 128 characters, only printable ASCII chars)
#define HEX "([a-zA-Z0-9.-]{1,128}): ([ -~]{1,128})\r\n"
//#define HEX "Content-Length: ([ -~]{1,128})\r\n"

/* CREATE SEPARATE REQUEST STRUCT TO STORE DATA FROM REGEX PARSING (LOOK AT REGEX PRACTICA)
    - should hold following data:
        - method, URI, version
        - content_length
        - message body (?, or offset to keep track where msg body starts)
*/

/* Pseudo for parsing module
    - init reg vars (regex, regmatch, rc; see practica)
    - compile regex with regcomp (defined Request-Line REGEX above)
    - run regexec to find matches in compiled regex and buf
    
    (FOR PARSING REQUEST LINE)
    - if matches exist (rc == 0? from practica)
        - pass in offsets for method, URI, and version
        - don't forget to null terminate matched strings (practica)
    - NO MATCHES :(
        - err print
        - exit with non zero
    
    (FOR PARSING HEADER FIELD)
    - comp new regex for header (defined Header-Field above)
    - run regexec to find matches
        - null terminate matched strings
    - check if "Content-Length" is parsed in
        - convert content after from str to int?
        
    (FOR PARSING MESSAGE BODY)
    - keep track of offset within previous parts of request
    - when calling put (update content of file passed in through socket, starting from 
      end of "Content-Length: value\r\n\r\n")
    - 
    
*/

/* Pseudocode for main
    
    - init listener socket obj
        - check for failure
    - init buffer to process read bytes from client
    
    - execute "forever" without crashing (until ctrl-c)
        - accept connection from client, getting socket int
            - check for err
        - process (read) bytes sent by client through socket into buffer
            - check read failure
        - parse request (using parsing module)
            - check for bad request
        - handle request
        - close current connection
        - clear buffer for next connection?
    */

typedef struct {
    // for BOTH
    char *method;
    char *uri;
    char *version;
    // for PUT
    char *key;
    int con_len;
    char *msg;
    int msg_bytes;
} Request;

// CITE @Vincent Section Slides for header
// Helper Function that reads until nbytes or \r\n\r\n is found in buf
ssize_t my_read(int in, char buf[], size_t nbytes) {
    ssize_t total_read = 0;

    while (total_read < (ssize_t) nbytes) {
        ssize_t curr_read = read(in, buf + total_read, nbytes - total_read);

        if (curr_read < 0) {
            return -1;
        } else if (curr_read == 0) {
            return total_read;
        }

        total_read += curr_read;

        if (strstr(buf, "\r\n\r\n")) {
            return total_read;
        }
    }

    return total_read;
}

// ---------------------------------------- PARSE ----------------------------------------------

// CITE @practica/regex for general structure of fxn
int parse_req(Request *req, int socket_fd, char buf[], ssize_t bytes_read) {
    //int parse_req(Request *req, int socket_fd, char buf[]) {
    regex_t re;
    regmatch_t req_matches[4];
    regmatch_t head_matches[3];
    int offset = 0;
    //int rc;

    // compile reg ex for REQUEST LINE
    int rc = regcomp(&re, REX, REG_EXTENDED);
    assert(!rc);

    // check for matches in REQUEST LINE
    rc = regexec(&re, buf, 4, req_matches, 0);

    // there are matches in REQUEST LINE
    if (rc == 0) {
        // set respective parts of request-line to Request struct and null terminate
        req->method = buf;
        req->method[req_matches[1].rm_eo] = '\0';
        //fprintf(stderr, "method: %s\n", req->method);

        req->uri = buf + req_matches[2].rm_so;
        req->uri[req_matches[2].rm_eo - req_matches[2].rm_so] = '\0';
        //fprintf(stderr, "uri: %s\n", req->uri);

        req->version = buf + req_matches[3].rm_so;
        req->version[req_matches[3].rm_eo - req_matches[3].rm_so] = '\0';
        //fprintf(stderr, "version: %s\n", req->version);

        // keep track of offset to know where msg_body starts
        offset += req_matches[3].rm_eo + 2;
    } else {
        req->method = NULL;
        req->uri = NULL;
        req->version = NULL;
        regfree(&re);
        write_n_bytes(
            socket_fd, "HTTP/1.1 400 Bad Request\r\nContent-Length: 12\r\n\r\nBad Request\n", 60);
        return 1;
    }

    // compile regex for HEADER FIELD and look for matches
    int rc2 = regcomp(&re, HEX, REG_EXTENDED);

    // adjust pointer in buf by current offset
    buf += offset;
    //fprintf(stderr, "buffer offset = %d\n", offset);

    // defaults
    char *valid_key = "Content-Length";
    int key_found = 0;

    // SEARCH FOR MATCHES AND PARSE IN HEADER FIELD
    // found out hard way there are multiple key:value pairs...
    // we have to keep looping until we find "Content-Length: Value"
    do {
        rc2 = regexec(&re, buf, 3, head_matches, 0);

        // there are no matches in the header field...
        // DO NOT CONTINUE WITH PARSING HEADR FIELD
        if (rc2 != 0) {
            break;
        }

        req->key = buf + head_matches[1].rm_so;
        req->key[head_matches[1].rm_eo - head_matches[1].rm_so] = '\0';
        //fprintf(stderr, "key: %s\n", req->key);

        // extract con_len
        buf[head_matches[1].rm_eo] = '\0';
        if (strncmp(req->key, valid_key, 14) == 0) {
            key_found = 1;
            buf[head_matches[2].rm_eo] = '\0';
            int val = strtol(buf + head_matches[2].rm_so, NULL, 10);
            req->con_len = val;
            //fprintf(stderr, "val: %d\n", val);
        }

        offset += head_matches[2].rm_eo + 2; // inc offset within request
        buf += head_matches[2].rm_eo + 2; // adjust pointer in buf before searching again

    } while (rc2 == 0 && key_found != 1);

    /* TRIED TO HARD CODE Content-Length: val HERE.... Failed
    if (rc2 == 0) {
        buf[head_matches[1].rm_eo] = '\0';
        int val = strtol(buf + head_matches[1].rm_so, NULL, 10);
        if (errno == EINVAL) {
            write_n_bytes(socket_fd, "HTTP/1.1 400 Bad Request\r\nContent-Length: 12\r\n\r\nBad Request\n", 60);
            return 1;
        }
        req->con_len = val;
        buf += head_matches[1].rm_eo + 2;
        offset += head_matches[1].rm_eo + 2;
    }
    */

    // debug prints
    //fprintf(stderr, "[DEBUG] buf: %s", buf);
    //buf += offset;
    //fprintf(stderr, "buffer offset 2 = %d\n", offset);

    // check for second \r\n after HEADER FIELD
    if ((buf[0] == '\r') && (buf[1] == '\n')) {
        buf += 2;
        offset += 2;
        req->msg = buf;
        req->msg[bytes_read] = '\0';
        req->msg_bytes = bytes_read - offset;
        fprintf(stderr, "[DEBUG] msg_bytes (1) = %d\n", req->msg_bytes);
    }
    /* else if ((rc2 != 0) && (buf[0] == '\r') && (buf[1] == '\n')) {  <---- PART OF FAILED HARD CODE
        buf += 2;
        offset += 2;
        req->msg = buf;
        req->msg[bytes_read] = '\0';
        req->msg_bytes = bytes_read - offset;
        //fprintf(stderr, "[DEBUG] msg_bytes (2) = %d\n", req->msg_bytes);
        //fprintf(stderr, "[DEBUG] buf: %.*s\n", req->msg_bytes, req->msg);
    } */
    else {
        write_n_bytes(
            socket_fd, "HTTP/1.1 400 Bad Request\r\nContent-Length: 12\r\n\r\nBad Request\n", 60);
        regfree(&re);
        return 1;
    }

    //fprintf(stderr, "[DEBUG] returning 0 at end of parse\n");
    regfree(&re);
    return 0;
}

// ------------------------------------------ GET ------------------------------------------------
void get(Request *req, int socket_fd) {

    // uri should not be a directory, this should fail...
    int fd = open(req->uri, O_DIRECTORY);
    if (fd != -1) {
        write_n_bytes(
            socket_fd, "HTTP/1.1 403 Forbidden\r\nContent-Length: 10\r\n\r\nForbidden\n", 56);
        return;
    }

    // checking for permission errors
    fd = open(req->uri, O_RDONLY);
    if (fd == -1) {
        if (errno == EACCES) {
            write_n_bytes(
                socket_fd, "HTTP/1.1 403 Forbidden\r\nContent-Length: 10\r\n\r\nForbidden\n", 56);
            return;
        } else if (errno == ENOENT) {
            write_n_bytes(
                socket_fd, "HTTP/1.1 404 Not Found\r\nContent-Length: 10\r\n\r\nNot Found\n", 56);
            return;
        }
        dprintf(socket_fd, "HTTP/1.1 500 Internal Server Error\r\nContent-Length: "
                           "22\r\n\r\nInternal Server Error\n");
        return;
    }
    fprintf(stderr, "file opened succesfully in GET\n");

    // check for additional input on GET method
    if (req->msg_bytes > 0 || req->con_len != -1) {
        write_n_bytes(
            socket_fd, "HTTP/1.1 400 Bad Request\r\nContent-Length: 12\r\n\r\nBad Request\n", 60);
        close(fd);
        return;
    }

    // open success and no additional input
    struct stat st;
    fstat(fd, &st);
    off_t file_size = st.st_size;
    dprintf(socket_fd, "HTTP/1.1 200 OK\r\nContent-Length: %ld\r\n\r\n", file_size);

    //fprintf(stderr, "[DEBUG] HTTP/1.1 200 OK\r\nContent-Length: %ld\r\n\r\n", file_size);

    // pass bytes from uri to socket
    int bytes_writ = pass_n_bytes(fd, socket_fd, file_size);
    if (bytes_writ == -1) {
        write_n_bytes(socket_fd,
            "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 22\r\n\r\nInternal Server "
            "Error\n",
            80);
        return;
    }

    close(fd);
    return;
}

// ------------------------------------------ PUT -----------------------------------------------------
void put(Request *req, int socket_fd) {
    // uri should not be a directory, this should fail...
    int fd = open(req->uri, O_DIRECTORY);
    if (fd != -1) {
        write_n_bytes(
            socket_fd, "HTTP/1.1 403 Forbidden\r\nContent-Length: 10\r\n\r\nForbidden\n", 56);
        return;
    }

    // check if file exists
    int file_created = 0;
    fd = open(req->uri, O_WRONLY | O_CREAT | O_EXCL, 0777);
    if (fd == -1) {
        // permission error accessing existing file
        if (errno == EACCES) {
            write_n_bytes(
                socket_fd, "HTTP/1.1 403 Forbidden\r\nContent-Length: 10\r\n\r\nForbidden\n", 56);
            return;
        }
        // file already exists
        else if (errno == EEXIST) {
            fd = open(req->uri, O_WRONLY | O_CREAT | O_TRUNC, 0777);
            if (fd == -1) {
                write_n_bytes(socket_fd,
                    "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 22\r\n\r\nInternal "
                    "Server "
                    "Error\n",
                    80);
                return;
            }
        }
    } else { // file created successfully
        file_created = 1;
    }

    // CITE @Vincent Section Slides

    // write contents from buf
    // msg->bytes is offset in buf for where msg_body starts
    // we flush out the buffer here of any extra content
    ssize_t bytes_writ = write_n_bytes(fd, req->msg, req->msg_bytes);

    // check if write failed
    if (bytes_writ == -1) {
        write_n_bytes(socket_fd,
            "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 22\r\n\r\nInternal Server "
            "Error\n",
            80);
        close(fd);
        return;
    }

    // pass content from socket
    // should only pass up to specified content length so passed bytes and
    // written bytes add up to content_length
    size_t to_pass = req->con_len - bytes_writ;
    ssize_t total_writ = pass_n_bytes(socket_fd, fd, to_pass);
    // check if pass failed
    if (total_writ == -1) {
        write_n_bytes(socket_fd,
            "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 22\r\n\r\nInternal Server "
            "Error\n",
            80);
        close(fd);
        return;
    }

    // if new file was created, print respective status
    if (file_created) {
        write_n_bytes(socket_fd, "HTTP/1.1 201 Created\r\nContent-Length: 8\r\n\r\nCreated\n", 51);
        //fprintf(stderr, "HTTP/1.1 201 Created\r\nContent-Length: 8\r\n\r\nCreated\n");
        close(fd);
        return;
    } else {
        write_n_bytes(socket_fd, "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nOK\n", 41);
        //fprintf(stderr, "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nOK\n");
        close(fd);
        return;
    }
}

// ------------------------------------- MAIN ----------------------------------------------

int main(int argc, char *argv[]) {
    // check for args
    if (argc != 2) { // fixed seg fault on bad input
        fprintf(stderr, "Invalid Port\n");
        return 1;
    }

    // create socket
    Listener_Socket socket;
    int port = strtol(argv[1], NULL, 10);
    if (port < 1 || port > 65535) {
        fprintf(stderr, "Invalid Port\n");
        return 1;
    }
    int socket_init = listener_init(&socket, port);
    if (socket_init == -1) {
        fprintf(stderr, "Invalid Port\n");
        return 1;
    }

    // execute forever
    while (1) {
        // accept connection
        int socket_fd = listener_accept(&socket);
        //printf("error: %s\n", strerror(errno));
        if (socket_fd == -1) {
            fprintf(stderr, "Failed connection\n");
            return 1;
        }

        // buffer w/ space for null-byte
        char buf[BUFFER_SIZE + 1];
        memset(buf, 0, BUFFER_SIZE + 1);

        // CITE @Vincent Section Slides
        // Use my_read function that reads until \r\n\r\n for entire request + header
        ssize_t bytes_read = my_read(socket_fd, buf, BUFFER_SIZE);
        //fprintf(stderr, "bytes_read = %zd\n", bytes_read);
        if (bytes_read == -1) {
            write_n_bytes(socket_fd,
                "HTTP/1.1 400 Bad Request\r\nContent-Length: 12\r\n\r\nBad Request\n", 60);
            return 1;
        }

        Request req;
        req.con_len = -1;
        int valid_req = parse_req(&req, socket_fd, buf, bytes_read);

        // request is valid
        if (valid_req == 0) {
            if ((strncmp(req.method, "GET", 3) != 0)
                && (strncmp(req.method, "PUT", 3) != 0)) { // bad method
                write_n_bytes(socket_fd,
                    "HTTP/1.1 501 Not Implemented\r\nContent-Length: 16\r\n\r\nNot Implemented\n",
                    68);
            } else if (strncmp(req.version, "HTTP/1.1", 8) != 0) { // bad version
                write_n_bytes(socket_fd,
                    "HTTP/1.1 505 Version Not Supported\r\nContent-Length: 22\r\n\r\nVersion Not "
                    "Supported\n",
                    80);
            } else if (strncmp(req.method, "GET", 3) == 0) { // if GET
                get(&req, socket_fd);
            } else if (strncmp(req.method, "PUT", 3) == 0) { // if PUT
                put(&req, socket_fd);
            }
        }

        // close connection
        close(socket_fd);
    }

    close(socket_init);
    return 0;
}
